"""Deterministic pinned source bundle for owner-side deployment builds.

This is a build INPUT, not an executable, rootfs or live-runtime receipt. External
Firecracker/kernel/rootfs/Python/toolchain bytes must be independently pinned by
an owner build environment; no fallback or network fetch occurs here.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile
from ..runtime.guest import canonical
from ..runtime.microvm import Blocked

# Mechanical closure includes only public infrastructure implementations. No
# research/private checkout, test vectors, scientific fixtures, secrets or DBs.
ROOT=Path(__file__).resolve().parents[3]
SOURCE_DIRS=('runtime','security','deployment')
EXTRA=('runner/assignment.py',)


def source_manifest(root=ROOT):
    root=Path(root);base=root/'infrastructure/t3'
    paths=[]
    for folder in SOURCE_DIRS:
        paths.extend(p for p in (base/folder).glob('*.py'))
    paths.extend(base/p for p in EXTRA)
    paths.append(base/'security/native_supervisor.c')
    out={}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():raise Blocked('BUILD_SOURCE_REGULAR_FILE')
        relative=path.relative_to(root).as_posix()
        out[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def build_bundle(expected_manifest,root=ROOT):
    """Exact source pins are mandatory; data output returned to owner CLI only."""
    observed=source_manifest(root)
    if type(expected_manifest) is not dict or expected_manifest!=observed:
        raise Blocked('BUILD_SOURCE_PIN_MISMATCH')
    root=Path(root);stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
        for relative in sorted(observed):
            path=root/relative
            if path.is_symlink():raise Blocked('BUILD_SOURCE_REGULAR_FILE')
            raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=observed[relative]:raise Blocked('BUILD_SOURCE_CHANGED')
            entry=zipfile.ZipInfo(relative,date_time=(1980,1,1,0,0,0))
            entry.create_system=3;entry.external_attr=0o100444<<16
            archive.writestr(entry,raw)
        receipt=canonical({'version':1,'status':'PINNED_SOURCE_BUILD_INPUT_ONLY',
                           'source_files':observed,'source_manifest_sha256':hashlib.sha256(canonical(observed)).hexdigest(),
                           'execution_authorized':False,'external_images_built':False})
        entry=zipfile.ZipInfo('build-input-receipt.json',(1980,1,1,0,0,0))
        entry.create_system=3;entry.external_attr=0o100444<<16
        archive.writestr(entry,receipt)
    value=stream.getvalue()
    return value,{'sha256':hashlib.sha256(value).hexdigest(),'size_bytes':len(value),
                  'status':'PINNED_SOURCE_BUILD_INPUT_ONLY','execution_authorized':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-manifest',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    expected=json.loads(Path(args.expected_manifest).read_text())
    value,receipt=build_bundle(expected)
    # Exclusive creation preserves original build inputs, even on duplicate use.
    with open(args.output,'xb') as f:f.write(value)
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':main()
