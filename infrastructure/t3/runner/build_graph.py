"""Offline pinned full-Runner build prerequisites. Never restores or runs a Job."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

BASE = pathlib.Path(__file__).resolve().parent
ROOT_PROJECTS = ('Runner.Listener/Runner.Listener.csproj', 'Runner.Worker/Runner.Worker.csproj')


def inspect(checkout):
    root = pathlib.Path(checkout).resolve()
    lock = json.loads((BASE/'upstream-lock.json').read_text())
    receipt = json.loads((BASE/'implementation_receipt.json').read_text())
    head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if head != lock['commit']:
        raise ValueError('BUILD_UPSTREAM_HEAD_MISMATCH')
    for relative, expected in receipt['patched_source_sha256'].items():
        if hashlib.sha256((root/relative).read_bytes()).hexdigest() != expected:
            raise ValueError('BUILD_PATCH_BYTES_MISMATCH')
    src = root/'src'; files={}; packages={}; projects=[]; missing=[]
    for name in ('global.json','Directory.Build.props'):
        actual=(src/name).read_bytes()
        upstream=subprocess.check_output(['git','show',head+':src/'+name],cwd=root)
        if actual != upstream: raise ValueError('BUILD_GLOBAL_INPUT_MODIFIED')
        files['src/'+name]=hashlib.sha256(actual).hexdigest()
    if json.loads((src/'global.json').read_text())['sdk']['version'] != lock['sdk']:
        raise ValueError('BUILD_SDK_MISMATCH')
    pending=[src/name for name in ROOT_PROJECTS];seen=set()
    while pending:
        project=pending.pop().resolve()
        if project in seen: continue
        seen.add(project)
        if not project.is_relative_to(src): raise ValueError('BUILD_REFERENCE_ESCAPE')
        relative=project.relative_to(root).as_posix(); raw=project.read_bytes()
        if raw != subprocess.check_output(['git','show',head+':'+relative],cwd=root):
            raise ValueError('BUILD_PROJECT_MODIFIED')
        files[relative]=hashlib.sha256(raw).hexdigest();projects.append(relative)
        tree=ET.fromstring(raw)
        for ref in tree.iter('ProjectReference'):
            pending.append(project.parent/ref.attrib['Include'].replace('\\','/'))
        for ref in tree.iter('PackageReference'):
            name=ref.attrib.get('Include'); version=ref.attrib.get('Version')
            if not name or not version or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.-]+)?',version):
                raise ValueError('BUILD_FLOATING_PACKAGE')
            packages.setdefault(name,set()).add(version)
        assets=project.parent/'obj/project.assets.json'
        if not assets.is_file(): missing.append(assets.relative_to(root).as_posix())
    # Existing assets alone do not prove a content-pinned, complete NuGet closure.
    return dict(kind='OFFLINE_RUNNER_BUILD_PREREQUISITES',upstream_commit=head,sdk=lock['sdk'],
        source_sha256=files,projects=sorted(projects),direct_packages={k:sorted(v) for k,v in sorted(packages.items())},
        missing_assets=sorted(missing),transitive_package_content_pins_verified=False,
        status='BLOCKED_MISSING_ASSETS' if missing else 'REQUIRES_TRANSITIVE_PACKAGE_VERIFICATION',
        full_runner_build_verified=False,network_requests=0,
        offline_build_argv=['dotnet','build','src/Runner.Listener/Runner.Listener.csproj','--no-restore','-c','Release',
            '-p:Version=2.338.0','-p:BuildNumber=0','-p:RuntimeIdentifiers=','-p:RuntimeIdentifier=','-p:SelfContained=false'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('checkout')
    print(json.dumps(inspect(parser.parse_args().checkout),sort_keys=True,indent=2))
