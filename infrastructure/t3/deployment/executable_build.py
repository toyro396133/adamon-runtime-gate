"""Build real embedded CPython ELF entrypoints with pinned owner toolchain.

This is not a source-bundle-to-executable relabel. A build without the real
Python development/runtime and compiler dependency closure fails before exec.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from .executable_image import original_file,inspect_elf
from ..runtime.microvm import Blocked

C_SOURCE=r'''#define PY_SSIZE_T_CLEAN
#include <Python.h>
int main(int argc,char **argv) {
 if(argc!=1)return 64;
 PyConfig c;PyConfig_InitIsolatedConfig(&c);
 c.use_environment=0;c.user_site_directory=0;c.site_import=0;c.safe_path=1;
 PyStatus s=PyConfig_SetString(&c,&c.home,L"/runtime/python");
 if(PyStatus_Exception(s))return 65;
 c.module_search_paths_set=1;
 s=PyWideStringList_Append(&c.module_search_paths,L"/runtime/python/lib/python3.12");
 if(PyStatus_Exception(s))return 65;
 s=PyWideStringList_Append(&c.module_search_paths,L"/runtime/python/lib/python3.12/lib-dynload");
 if(PyStatus_Exception(s))return 65;
 s=PyWideStringList_Append(&c.module_search_paths,L"/runtime/python/lib/python3.12/site-packages");
 if(PyStatus_Exception(s))return 65;
 s=PyWideStringList_Append(&c.module_search_paths,L"/source");
 if(PyStatus_Exception(s))return 65;
 s=Py_InitializeFromConfig(&c);PyConfig_Clear(&c);
 if(PyStatus_Exception(s))return 66;
 int status=PyRun_SimpleString("from infrastructure.t3.deployment.bootstrap_entry import main\nmain('ROLE')\n");
 if(Py_FinalizeEx()<0)return 67;
 return status?70:0;
}
'''


def build_executable(*,role,root,manifest,output):
    if role not in {'OWNER','LAUNCHER'}:raise Blocked('EXECUTABLE_ROLE')
    if type(manifest) is not dict or set(manifest)!={'version','files','compiler','python_include','python_library','runtime_files'} or manifest['version']!=1:raise Blocked('EXECUTABLE_BUILD_SCHEMA')
    root=Path(root)
    files=manifest['files']
    if type(files) is not dict or not files:raise Blocked('EXECUTABLE_TOOLCHAIN_CLOSURE')
    for name,digest in files.items():
        if type(name) is not str or name.startswith('/') or '..' in name.split('/'):raise Blocked('EXECUTABLE_TOOLCHAIN_PATH')
        original_file(root/name,digest)
    required={manifest['compiler'],manifest['python_include']+'/Python.h',manifest['python_library']}
    if not required<=set(files):raise Blocked('EXECUTABLE_TOOLCHAIN_MISSING')
    # Compiler can invoke cc1/as/ld and read unlisted headers. Refuse an ambient
    # tree: the owner manifest must enumerate every regular file, no symlinks.
    actual=set()
    for path in root.rglob('*'):
        if path.is_symlink():raise Blocked('EXECUTABLE_TOOLCHAIN_SYMLINK')
        if path.is_file():actual.add(path.relative_to(root).as_posix())
    if actual!=set(files):raise Blocked('EXECUTABLE_TOOLCHAIN_UNDECLARED')
    output=Path(output)
    if output.exists():raise Blocked('EXECUTABLE_OUTPUT_EXISTS')
    output.mkdir(mode=0o700,parents=False)
    source=output/'entry.c';source.write_text(C_SOURCE.replace('ROLE',role),encoding='ascii')
    target=output/'entry.elf'
    # Fixed argv, no shell, plugin, caller flags or script. Owner toolchain must
    # live on a read-only filesystem for the entire build (including helpers).
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
        if not os.fstatvfs(fd).f_flag&os.ST_RDONLY:raise Blocked('EXECUTABLE_TOOLCHAIN_NOT_READONLY')
    finally:os.close(fd)
    command=[str(root/manifest['compiler']),'-Werror','-O2','-fPIE','-pie','-Wl,-z,relro,-z,now','-Wl,-rpath,/runtime/python/lib','-I'+str(root/manifest['python_include']),str(source),str(root/manifest['python_library']),'-o',str(target)]
    result=subprocess.run(command,env={'PATH':str(root/'bin'),'LC_ALL':'C','SOURCE_DATE_EPOCH':'0'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    (output/'build.log').write_bytes(result.stdout)
    if result.returncode:raise Blocked('EXECUTABLE_COMPILER_FAILED')
    raw=target.read_bytes();info=inspect_elf(raw)
    if info['interpreter'] is not None and info['interpreter'] not in manifest['runtime_files']:raise Blocked('EXECUTABLE_LOADER_UNDECLARED')
    receipt={'version':1,'role':role,'scope':'OWNER_NONRESEARCH_ENTRY_IMAGE','elf_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'toolchain_manifest_sha256':hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'runtime_files':manifest['runtime_files'],'inspection':info,'exit_code':result.returncode,'research_authorized':False,'runtime_verified':False}
    (output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='Owner-only pinned CPython ELF packaging; no execution')
    parser.add_argument('--role',choices=('OWNER','LAUNCHER'),required=True)
    parser.add_argument('--toolchain-root',required=True)
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise Blocked('EXECUTABLE_BUILD_DUPLICATE_FIELD')
            result[key]=value
        return result
    manifest=json.loads(Path(args.manifest).read_bytes(),object_pairs_hook=unique)
    receipt=build_executable(role=args.role,root=args.toolchain_root,manifest=manifest,output=args.output)
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':main()
