"""Owner-only, offline, fixed nonresearch rootfs assembly command.

Requires an owner-supplied base-tree manifest (including Python, cryptography,
OpenSSL and loader bytes) and pinned mke2fs. No downloads, image pulling, shell,
Workflow configuration or automatic provision. Exact source pins are required.
Image reproducibility must be checked by two independent builds; this module
records bytes and does not infer reproducibility from a successful exit alone.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from ..runtime.guest import canonical
from ..runtime.microvm import Blocked
from .build_bundle import build_bundle,source_manifest

INIT=b'#!/usr/bin/python3\nimport sys\nsys.path.insert(0,"/opt/adamon")\nfrom infrastructure.t3.deployment.nonresearch_images import guest_init\nguest_init()\n'


def verify_base(base,expected):
    """Closed regular-file base; no archive extraction, symlink traversal or devices."""
    base=Path(base)
    if base.is_symlink() or not base.is_dir():raise Blocked('ROOTFS_BASE_DIRECTORY')
    if type(expected) is not dict or not expected:raise Blocked('ROOTFS_BASE_MANIFEST')
    observed={}
    for path in sorted(base.rglob('*')):
        st=path.lstat()
        if stat.S_ISLNK(st.st_mode) or (not stat.S_ISREG(st.st_mode) and not stat.S_ISDIR(st.st_mode)) or st.st_mode&0o6000:
            raise Blocked('ROOTFS_BASE_UNSAFE_MEMBER')
        if path.is_file():
            observed[path.relative_to(base).as_posix()]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'mode':stat.S_IMODE(st.st_mode)}
    if observed!=expected:raise Blocked('ROOTFS_BASE_PIN_MISMATCH')
    required={'usr/bin/python3','usr/lib/python3.12/os.py'}
    if not required<=set(observed) or not observed['usr/bin/python3']['mode']&0o111:
        raise Blocked('ROOTFS_PINNED_PYTHON_MISSING')
    return observed


def assemble_tree(base,expected_base,expected_source,owner_public_key,staging,source_root=None):
    if type(owner_public_key) is not bytes or len(owner_public_key)!=32:
        raise Blocked('ROOTFS_OWNER_PUBLIC_KEY')
    source_root=Path(source_root) if source_root is not None else Path(__file__).resolve().parents[3]
    verify_base(base,expected_base)
    bundle,_=build_bundle(expected_source,source_root)
    staging=Path(staging)
    if staging.exists():raise Blocked('ROOTFS_STAGING_EXISTS')
    shutil.copytree(base,staging,symlinks=False)
    # Recheck exact copied base; a concurrently changed byte cannot become a
    # trusted image merely because the original tree was valid at an earlier time.
    verify_base(staging,expected_base)
    import io,zipfile
    target=staging/'opt/adamon';target.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        for name in expected_source:
            path=target/name;path.parent.mkdir(parents=True,exist_ok=True)
            with open(path,'xb') as f:f.write(archive.read(name))
            path.chmod(0o444)
    for name in ('infrastructure/__init__.py','infrastructure/t3/__init__.py'):
        path=target/name
        if not path.exists():path.write_bytes(b'');path.chmod(0o444)
    (staging/'sbin').mkdir(exist_ok=True)
    with open(staging/'sbin/init','xb') as f:f.write(INIT)
    (staging/'sbin/init').chmod(0o555)
    with open(staging/'owner-public-key','xb') as f:f.write(owner_public_key)
    (staging/'owner-public-key').chmod(0o444)
    for name in ('dev','proc','sys','run','tmp'): (staging/name).mkdir(exist_ok=True)
    # Fixed timestamps feed mke2fs -d rather than exposing build-wall-clock time.
    for path in staging.rglob('*'):os.utime(path,(1,1),follow_symlinks=False)
    os.utime(staging,(1,1))
    return {'source_manifest_sha256':hashlib.sha256(canonical(expected_source)).hexdigest(),
            'base_manifest_sha256':hashlib.sha256(canonical(expected_base)).hexdigest(),
            'owner_public_key_sha256':hashlib.sha256(owner_public_key).hexdigest(),
            'init_sha256':hashlib.sha256(INIT).hexdigest()}


def build_ext4(staging,output,mke2fs_path,mke2fs_sha256):
    # Owner CLI paths are local build inputs, never runtime/Workflow RPC fields.
    # Use exact verified descriptor through exec to avoid binary pathname TOCTOU.
    fd=os.open(mke2fs_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    sealed=None
    try:
        raw=os.pread(fd,16*1024*1024,0)
        if os.fstat(fd).st_size>len(raw) or hashlib.sha256(raw).hexdigest()!=mke2fs_sha256:
            raise Blocked('ROOTFS_MKE2FS_PIN')
        import fcntl
        sealed=os.memfd_create('owner-pinned-mke2fs',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        view=memoryview(raw)
        while view:
            count=os.write(sealed,view)
            if count<=0:raise Blocked('ROOTFS_TOOL_WRITE')
            view=view[count:]
        os.fchmod(sealed,0o555);fcntl.fcntl(sealed,1033,15)
        out=os.open(output,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        try:
            os.ftruncate(out,256*1024*1024)
            subprocess.run(['mke2fs','-q','-t','ext4','-F','-b','4096',
                            '-U','579cda74-0e44-436a-894a-81d752cd040a',
                            '-E','lazy_itable_init=0,lazy_journal_init=0',
                            '-d',str(Path(staging).resolve()),'/proc/self/fd/'+str(out)],
                           executable='/proc/self/fd/'+str(sealed),pass_fds=(sealed,out),
                           stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=120,
                           env={'PATH':'/nonexistent','LC_ALL':'C','E2FSPROGS_FAKE_TIME':'1','SOURCE_DATE_EPOCH':'1'})
            os.fsync(out)
            digest=hashlib.sha256();offset=0
            while True:
                block=os.pread(out,1024*1024,offset)
                if not block:break
                digest.update(block);offset+=len(block)
            return {'sha256':digest.hexdigest(),'size_bytes':offset,
                    'status':'NONRESEARCH_ROOTFS_BYTES_BUILT_PENDING_REPRODUCIBILITY_AND_BOOT',
                    'live_boot_verified':False,'execution_authorized':False}
        finally:os.close(out)
    finally:
        if sealed is not None:os.close(sealed)
        os.close(fd)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('base','base-manifest','source-manifest','owner-public-key','staging','output','mke2fs','mke2fs-sha256'):
        p.add_argument('--'+flag,required=True)
    a=p.parse_args(argv)
    pins=assemble_tree(a.base,json.loads(Path(a.base_manifest).read_text()),
                       json.loads(Path(a.source_manifest).read_text()),
                       Path(a.owner_public_key).read_bytes(),a.staging)
    receipt=build_ext4(a.staging,a.output,a.mke2fs,a.mke2fs_sha256)
    print(json.dumps({'build_inputs':pins,'output':receipt},sort_keys=True))


if __name__=='__main__':main()
