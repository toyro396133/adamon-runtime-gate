"""Owner build handoff. No restore, provision, workflow or Runner execution here.

Dependency discovery is explicitly untrusted until every lock's contentHash is
verified against the original nupkg bytes. Receipts require original TRX/output.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import struct
import xml.etree.ElementTree as ET
from .build_graph import BASE, inspect

VERSION = re.compile(r'[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.-]+)?$')
NAME = re.compile(r'[A-Za-z0-9_.-]+$')

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def validate_managed_pe(raw):
    """Structural validation only; neither a build nor code provenance proof."""
    try:
        if raw[:2]!=b'MZ' or len(raw)<64: raise ValueError
        pe=struct.unpack_from('<I',raw,60)[0]
        if raw[pe:pe+4]!=b'PE\0\0': raise ValueError
        sections=struct.unpack_from('<H',raw,pe+6)[0]
        optional_size=struct.unpack_from('<H',raw,pe+20)[0]
        optional=pe+24
        magic=struct.unpack_from('<H',raw,optional)[0]
        directory_offset={0x10b:96,0x20b:112}[magic]
        if optional_size<directory_offset+15*8 or not 0<sections<=96: raise ValueError
        count=struct.unpack_from('<I',raw,optional+directory_offset-4)[0]
        if count<15: raise ValueError
        cli_rva,cli_size=struct.unpack_from('<II',raw,optional+directory_offset+14*8)
        if cli_size<72: raise ValueError
        def mapped(rva,size):
            matches=[]
            for index in range(sections):
                offset=optional+optional_size+index*40
                _,start,length,position=struct.unpack_from('<IIII',raw,offset+8)
                if start<=rva and rva+size<=start+length:
                    at=position+rva-start
                    if at+size>len(raw): raise ValueError
                    matches.append(at)
            if len(matches)!=1: raise ValueError
            return matches[0]
        cli=mapped(cli_rva,cli_size)
        if struct.unpack_from('<I',raw,cli)[0]<72: raise ValueError
        metadata_rva,metadata_size=struct.unpack_from('<II',raw,cli+8)
        if metadata_size<20: raise ValueError
        metadata=mapped(metadata_rva,metadata_size)
        if raw[metadata:metadata+4]!=b'BSJB': raise ValueError
    except (ValueError,KeyError,struct.error):
        raise ValueError('BUILD_OUTPUT_NOT_MANAGED_PE') from None

def dependency_closure(checkout, feed):
    """Validate all nine upstream project lockfiles and byte-pinned local feed."""
    root = pathlib.Path(checkout).resolve()
    feed = pathlib.Path(feed).resolve()
    projects = sorted((root/'src').rglob('*.csproj'))
    # Exclude platform service projects absent from the pinned solution graph.
    solution = (root/'src/ActionsRunner.sln').read_text()
    projects = [p for p in projects if p.relative_to(root/'src').as_posix().replace('/', '\\') in solution and 'Runner.Service' not in p.parts]
    if not projects: raise ValueError('BUILD_PROJECT_CLOSURE_EMPTY')
    locks = {}; packages = {}
    for project in projects:
        lock = project.parent/'packages.lock.json'
        if not lock.is_file(): raise ValueError('BUILD_LOCK_MISSING')
        value = json.loads(lock.read_bytes())
        if value.get('version') not in (1, 2) or not value.get('dependencies'):
            raise ValueError('BUILD_LOCK_FORMAT')
        locks[lock.relative_to(root).as_posix()] = digest(lock)
        for framework, dependencies in value['dependencies'].items():
            if not isinstance(framework,str) or not isinstance(dependencies,dict): raise ValueError('BUILD_LOCK_FORMAT')
            for name, spec in dependencies.items():
                if spec.get('type') == 'Project': continue
                version = spec.get('resolved')
                if not NAME.fullmatch(name) or not isinstance(version,str) or not VERSION.fullmatch(version):
                    raise ValueError('BUILD_FLOATING_TRANSITIVE_PACKAGE')
                if spec.get('type') not in ('Direct','Transitive'): raise ValueError('BUILD_PACKAGE_TYPE')
                content = spec.get('contentHash')
                try: expected = base64.b64decode(content,validate=True)
                except (TypeError,ValueError): raise ValueError('BUILD_CONTENT_HASH_MISSING') from None
                if len(expected)!=64: raise ValueError('BUILD_CONTENT_HASH_INVALID')
                package = feed/(name.lower()+'.'+version.lower()+'.nupkg')
                if package.is_symlink() or not package.is_file(): raise ValueError('BUILD_PACKAGE_MISSING')
                raw=package.read_bytes()
                if hashlib.sha512(raw).digest()!=expected: raise ValueError('BUILD_PACKAGE_BYTES_MISMATCH')
                key=name.lower()+'/'+version.lower()
                item=dict(sha256=hashlib.sha256(raw).hexdigest(),sha512_base64=content,size_bytes=len(raw))
                if key in packages and packages[key]!=item: raise ValueError('BUILD_PACKAGE_CONFLICT')
                packages[key]=item
    return dict(lock_sha256=locks,packages=packages,projects=[p.relative_to(root).as_posix() for p in projects])

def create(checkout, sdk, feed=None):
    prerequisites=inspect(checkout)
    sdk=pathlib.Path(sdk).resolve()
    receipt=json.loads((BASE/'implementation_receipt.json').read_bytes())
    if digest(sdk)!=receipt['dotnet_host_sha256']: raise ValueError('BUILD_SDK_HOST_BYTES_MISMATCH')
    version=subprocess.check_output([str(sdk),'--version'],cwd=pathlib.Path(checkout)/'src',text=True).strip()
    if version!=prerequisites['sdk']: raise ValueError('BUILD_SDK_VERSION_MISMATCH')
    root=pathlib.Path(checkout).resolve()
    # Original build entry and full solution/test graph must also be exact upstream.
    sources=dict(prerequisites['source_sha256'])
    for path in sorted((root/'src').rglob('*.csproj'))+[root/'src/ActionsRunner.sln',root/'src/dir.proj']:
        relative=path.relative_to(root).as_posix()
        original=subprocess.check_output(['git','show',prerequisites['upstream_commit']+':'+relative],cwd=root)
        if path.read_bytes()!=original: raise ValueError('BUILD_FULL_GRAPH_MODIFIED')
        sources[relative]=digest(path)
    closure=dependency_closure(root,feed) if feed else None
    # These are argv arrays, executed only by the separately authorized owner.
    common=['-p:RestoreLockedMode=true','-p:RestorePackagesWithLockFile=true','-p:RestoreSources='+str(pathlib.Path(feed).resolve())] if feed else []
    commands=[dict(phase='restore_test',argv=[str(sdk),'restore','src/Test/Test.csproj','--use-lock-file','-p:PackageRuntime=linux-x64']+common),
        dict(phase='restore_pluginhost',argv=[str(sdk),'restore','src/Runner.PluginHost/Runner.PluginHost.csproj','--use-lock-file','-p:PackageRuntime=linux-x64']+common),
        dict(phase='build',argv=[str(sdk),'msbuild','src/dir.proj','-t:Build','-p:PackageRuntime=linux-x64','-p:BUILDCONFIG=Release','-p:RunnerVersion=2.338.0']+common),
        dict(phase='tests',argv=[str(sdk),'test','src/Test/Test.csproj','-c','Release','--logger:trx','-p:PackageRuntime=linux-x64']+common)]
    return dict(version=1,kind='OWNER_RUNNER_BUILD_BUNDLE',upstream_commit=prerequisites['upstream_commit'],
        patch_sha256=digest(BASE/'runner-v4.patch'),overlay_sha256=digest(BASE/'overlays/P4ProtectedBridge.cs'),
        source_sha256=sources,sdk_version=version,sdk_host_sha256=digest(sdk),
        sdk_archive_sha512=receipt['sdk_archive_sha512_verified'],dependency_closure=closure,commands=commands,
        status='CONTENT_PINNED_READY_FOR_OWNER_BUILD' if closure else 'BLOCKED_UNFROZEN_TRANSITIVE_CONTENT',
        full_runner_build_verified=False,execution_authorized=False,
        resource_blocker=dict(workspace_free_bytes=__import__('shutil').disk_usage(root).free,
            note='Restore previously ENOSPC; do not retry on this resource-constrained host. Owner host policy applies.'))

def verify_build_receipt(bundle, receipt, evidence_root):
    """Read original owner outputs; validation is not independent acceptance."""
    if bundle.get('status')!='CONTENT_PINNED_READY_FOR_OWNER_BUILD' or not bundle.get('dependency_closure'):
        raise ValueError('BUILD_DEPENDENCIES_NOT_FROZEN')
    if set(receipt)!={'version','bundle_sha256','phases','outputs','trx'} or receipt['version']!=1:
        raise ValueError('BUILD_RECEIPT_SCHEMA')
    canonical=json.dumps(bundle,sort_keys=True,separators=(',',':')).encode()
    if receipt['bundle_sha256']!=hashlib.sha256(canonical).hexdigest(): raise ValueError('BUILD_RECEIPT_BUNDLE_MISMATCH')
    root=pathlib.Path(evidence_root).resolve()
    def read(ref):
        if set(ref)!={'relative','sha256','size_bytes'}: raise ValueError('BUILD_ARTIFACT_SCHEMA')
        rel=pathlib.PurePosixPath(ref['relative'])
        if rel.is_absolute() or '..' in rel.parts: raise ValueError('BUILD_ARTIFACT_ESCAPE')
        path=root/rel
        if any(p.is_symlink() for p in [path,*path.parents] if p!=root.parent): raise ValueError('BUILD_ARTIFACT_SYMLINK')
        raw=path.read_bytes()
        if len(raw)!=ref['size_bytes'] or hashlib.sha256(raw).hexdigest()!=ref['sha256']: raise ValueError('BUILD_ARTIFACT_BYTES_MISMATCH')
        return raw
    if set(receipt['phases'])!={c['phase'] for c in bundle['commands']}: raise ValueError('BUILD_PHASE_MISSING')
    for expected in bundle['commands']:
        phase=receipt['phases'][expected['phase']]
        if set(phase)!={'argv','exit_code','log'} or phase['argv']!=expected['argv'] or type(phase['exit_code']) is not int or phase['exit_code']!=0:
            raise ValueError('BUILD_PHASE_FAILED')
        if not read(phase['log']): raise ValueError('BUILD_LOG_EMPTY')
    if set(receipt['outputs'])!={'Runner.Listener.dll','Runner.Worker.dll'}: raise ValueError('BUILD_OUTPUT_MISSING')
    for ref in receipt['outputs'].values():
        validate_managed_pe(read(ref))
    trx=ET.fromstring(read(receipt['trx']))
    counter_nodes=trx.findall('.//{*}Counters')
    if len(counter_nodes)!=1: raise ValueError('BUILD_TEST_RESULTS_MISSING')
    counters=counter_nodes[0]
    try: total=int(counters.attrib['total']);passed=int(counters.attrib['passed']);executed=int(counters.attrib['executed'])
    except (KeyError,ValueError): raise ValueError('BUILD_TEST_RESULTS_MISSING') from None
    if total<=0 or passed!=total or executed!=total: raise ValueError('BUILD_TESTS_INCOMPLETE')
    for name in ('failed','error','timeout','aborted','inconclusive','notExecuted','disconnected','warning','pending'):
        try: value=int(counters.attrib.get(name,'0'))
        except ValueError: raise ValueError('BUILD_TESTS_INCOMPLETE') from None
        if value!=0: raise ValueError('BUILD_TESTS_INCOMPLETE')
    results=trx.findall('.//{*}UnitTestResult')
    identifiers=[result.attrib.get('executionId') for result in results]
    if len(results)!=total or any(result.attrib.get('outcome')!='Passed' for result in results) or any(not value for value in identifiers) or len(set(identifiers))!=total:
        raise ValueError('BUILD_TEST_RESULTS_INCONSISTENT')
    return dict(status='OWNER_BUILD_OUTPUTS_VALIDATED_PENDING_INDEPENDENT_REVIEW',tests_passed=passed,
        execution_authorized=False,research_executed=False)

def export_feed(checkout, package_cache, output):
    """Owner-only copy of original cached nupkg, after full lock hash validation.

    This does not download anything. The fresh private output must not exist.
    Never overwrite historical packages or owner cache.
    """
    import shutil
    import tempfile
    root=pathlib.Path(checkout).resolve(); cache=pathlib.Path(package_cache).resolve()
    output=pathlib.Path(output).absolute()
    if output.exists() or output.is_symlink(): raise ValueError('BUILD_FEED_OUTPUT_EXISTS')
    solution=(root/'src/ActionsRunner.sln').read_text()
    selected={}
    for project in sorted((root/'src').rglob('*.csproj')):
        if 'Runner.Service' in project.parts or project.relative_to(root/'src').as_posix().replace('/', '\\') not in solution: continue
        lock=project.parent/'packages.lock.json'
        if not lock.is_file(): raise ValueError('BUILD_LOCK_MISSING')
        for deps in json.loads(lock.read_bytes()).get('dependencies',{}).values():
            for name,spec in deps.items():
                if spec.get('type')=='Project': continue
                version=spec.get('resolved')
                if not NAME.fullmatch(name) or not isinstance(version,str) or not VERSION.fullmatch(version): raise ValueError('BUILD_FLOATING_TRANSITIVE_PACKAGE')
                filename=name.lower()+'.'+version.lower()+'.nupkg'
                path=cache/name.lower()/version.lower()/filename
                if path.is_symlink() or not path.is_file(): raise ValueError('BUILD_PACKAGE_MISSING')
                selected[filename]=path
    with tempfile.TemporaryDirectory(prefix='owner-runner-feed-',dir=output.parent) as staging:
        staging=pathlib.Path(staging)
        for filename,path in selected.items(): shutil.copyfile(path,staging/filename)
        closure=dependency_closure(root,staging)
        # The output is created exclusively only after all original bytes pass.
        output.mkdir(mode=0o700)
        for package in staging.iterdir():
            with (output/package.name).open('xb') as target: target.write(package.read_bytes())
    return closure

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--checkout');p.add_argument('--sdk');p.add_argument('--feed')
    p.add_argument('--export-feed',action='store_true');p.add_argument('--package-cache');p.add_argument('--output')
    p.add_argument('--verify-receipt');p.add_argument('--bundle');p.add_argument('--evidence-root')
    args=p.parse_args()
    if args.export_feed:
        if args.verify_receipt or not all((args.checkout,args.package_cache,args.output)):
            p.error('export requires checkout, package-cache and fresh output')
        result=export_feed(args.checkout,args.package_cache,args.output)
    elif args.verify_receipt:
        if not all((args.bundle,args.evidence_root)): p.error('verification requires bundle and evidence-root')
        result=verify_build_receipt(json.loads(pathlib.Path(args.bundle).read_bytes()),
            json.loads(pathlib.Path(args.verify_receipt).read_bytes()),args.evidence_root)
    else:
        if not all((args.checkout,args.sdk)): p.error('inspection requires checkout and sdk')
        result=create(args.checkout,args.sdk,args.feed)
    print(json.dumps(result,sort_keys=True,indent=2))
