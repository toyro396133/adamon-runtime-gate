"""Explicit owner-only full Runner builder; never launches a Runner or research.

No shell/command input. Revalidates the pinned source/SDK/feed before each phase.
Partial original logs are retained on failure. Requires a fresh output directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
from .build_bundle import create, verify_build_receipt


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def reference(root, path):
    raw = path.read_bytes()
    return dict(relative=path.relative_to(root).as_posix(), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))


def validate_bundle(bundle, checkout, sdk, feed):
    fresh = create(checkout, sdk, feed)
    # Available capacity is diagnostic, not authority; everything else is exact.
    for value in (fresh, bundle):
        if value.get('status') != 'CONTENT_PINNED_READY_FOR_OWNER_BUILD':
            raise ValueError('OWNER_BUILD_MATERIALS_INCOMPLETE')
    if {k:v for k,v in fresh.items() if k != 'resource_blocker'} != {k:v for k,v in bundle.items() if k != 'resource_blocker'}:
        raise ValueError('OWNER_BUILD_AUTHORITY_CHANGED')


def environment(output, sdk):
    """Do not inherit HOME, PATH, NuGet caches, MSBuild or proxy injection."""
    home = output/'home'
    home.mkdir(mode=0o700)
    return {'HOME':str(home), 'PATH':str(Path(sdk).resolve().parent)+':/usr/bin:/bin', 'LANG':'C.UTF-8',
        'DOTNET_ROOT':str(Path(sdk).resolve().parent),
        'DOTNET_CLI_HOME':str(home), 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1',
        'DOTNET_CLI_TELEMETRY_OPTOUT':'1', 'DOTNET_NOLOGO':'1',
        'NUGET_PACKAGES':str(output/'packages'),
        'NUGET_HTTP_CACHE_PATH':str(output/'http-cache'),
        'NUGET_PLUGINS_CACHE_PATH':str(output/'plugin-cache'),
        'MSBUILDDISABLENODEREUSE':'1'}


def missing_materials(checkout, feed):
    """Deterministic missing-file inventory; never downloads or fabricates locks."""
    root=Path(checkout);feed=Path(feed)
    solution=root/'src/ActionsRunner.sln'
    if not solution.is_file():
        return ['src/ActionsRunner.sln']
    text=solution.read_text()
    missing=set()
    for project in sorted((root/'src').rglob('*.csproj')):
        if 'Runner.Service' in project.parts or project.relative_to(root/'src').as_posix().replace('/', chr(92)) not in text:
            continue
        lock=project.parent/'packages.lock.json'
        if not lock.is_file():
            missing.add(lock.relative_to(root).as_posix());continue
        dependencies=json.loads(lock.read_bytes()).get('dependencies',{})
        for framework in dependencies.values():
            for name,spec in framework.items():
                if spec.get('type')=='Project':continue
                version=spec.get('resolved')
                if not isinstance(version,str):
                    missing.add(lock.relative_to(root).as_posix()+':unresolved:'+name);continue
                filename=name.lower()+'.'+version.lower()+'.nupkg'
                if not (feed/filename).is_file():missing.add('feed/'+filename)
    return sorted(missing)


def run(bundle, checkout, sdk, feed, output, *, timeout=3600):
    if type(timeout) is not int or not 1 <= timeout <= 21600:
        raise ValueError('OWNER_BUILD_TIMEOUT')
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('OWNER_BUILD_OUTPUT_EXISTS')
    validate_bundle(bundle, checkout, sdk, feed)
    # Fail before restore on the previously exhausted environment.
    if shutil.disk_usage(Path(checkout)).free < 16*1024**3:
        raise ValueError('OWNER_BUILD_CAPACITY_BELOW_16_GIB')
    if list((Path(checkout)/'src/Test/TestResults').glob('*.trx')):
        raise ValueError('OWNER_BUILD_STALE_TRX')
    if (Path(checkout)/'_layout').exists():
        raise ValueError('OWNER_BUILD_REQUIRES_FRESH_LAYOUT')
    if any((Path(checkout)/'src').rglob('project.assets.json')):
        raise ValueError('OWNER_BUILD_REQUIRES_FRESH_ASSETS')
    output.mkdir(mode=0o700)
    env = environment(output, sdk)
    # NuGet configuration is closed to the byte-verified local feed.
    from xml.sax.saxutils import escape
    config = output/'NuGet.Config'
    config.write_text('<configuration><packageSources><clear/><add key="locked" value="'+escape(str(Path(feed).resolve()), {'"':'&quot;'})+'"/></packageSources><packageSourceMapping><packageSource key="locked"><package pattern="*"/></packageSource></packageSourceMapping></configuration>')
    env['NUGET_CONFIG_FILE'] = str(config)
    receipt = dict(version=1,bundle_sha256=hashlib.sha256(canonical(bundle)).hexdigest(),phases={},outputs={},trx={})
    for phase in bundle['commands']:
        validate_bundle(bundle, checkout, sdk, feed)
        argv = phase['argv']
        log = output/(phase['phase']+'.log')
        # Fresh cache and explicit restore sources keep ambient configuration out.
        with log.open('xb') as stream:
            try:
                process = subprocess.Popen(argv, cwd=Path(checkout), env=env,
                    stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    code = 124
            except OSError as error:
                stream.write(('OWNER_BUILD_EXEC_ERROR:'+str(error.errno)+'\n').encode())
                code = 126
        receipt['phases'][phase['phase']] = dict(argv=argv,exit_code=code,log=reference(output,log))
        (output/'partial-receipt.json').write_bytes(canonical(receipt))
        if code:
            return dict(status='OWNER_BUILD_FAILED_OR_TIMEOUT', phase=phase['phase'],exit_code=code,partial_receipt=receipt,research_executed=False)
    for name in ('Runner.Listener.dll','Runner.Worker.dll'):
        published=Path(checkout)/'_layout/bin'/name
        matches=[published] if published.is_file() and not published.is_symlink() else []
        if len(matches)!=1: raise ValueError('OWNER_BUILD_OUTPUT_AMBIGUOUS_OR_MISSING')
        target=output/name
        with target.open('xb') as stream: stream.write(matches[0].read_bytes())
        receipt['outputs'][name]=reference(output,target)
    results=list((Path(checkout)/'src/Test/TestResults').glob('*.trx'))
    if len(results)!=1: raise ValueError('OWNER_BUILD_TRX_AMBIGUOUS_OR_MISSING')
    target=output/'results.trx'
    with target.open('xb') as stream: stream.write(results[0].read_bytes())
    receipt['trx']=reference(output,target)
    validation=verify_build_receipt(bundle,receipt,output)
    (output/'receipt.json').write_bytes(canonical(receipt))
    (output/'validation.json').write_bytes(canonical(validation))
    return validation


def main():
    parser=argparse.ArgumentParser()
    for name in ('bundle','checkout','sdk','feed','output'): parser.add_argument('--'+name,required=True)
    parser.add_argument('--timeout',type=int,default=3600)
    args=parser.parse_args()
    result=run(json.loads(Path(args.bundle).read_bytes()),args.checkout,args.sdk,args.feed,args.output,timeout=args.timeout)
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0 if result['status']=='OWNER_BUILD_OUTPUTS_VALIDATED_PENDING_INDEPENDENT_REVIEW' else 1

if __name__=='__main__':
    raise SystemExit(main())
