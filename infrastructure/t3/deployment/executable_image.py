"""Linux executable images: verified ELF, never source ZIP/script substitution.

Owner paths are build inputs only. They are never a Workflow-selected command.
The native executor receives the sealed descriptor returned here.
"""
import fcntl
import hashlib
import os
import stat
import struct
from ..runtime.microvm import Blocked


def inspect_elf(raw):
    if type(raw) is not bytes or len(raw)<64 or raw[:7]!=b'\x7fELF\x02\x01\x01':
        raise Blocked('EXECUTABLE_NOT_LINUX_ELF64')
    kind,machine=struct.unpack_from('<HH',raw,16)
    if kind not in (2,3) or machine!=62:raise Blocked('EXECUTABLE_ARCH_OR_TYPE')
    off=struct.unpack_from('<Q',raw,32)[0]
    entry_size,count=struct.unpack_from('<HH',raw,54)
    if entry_size!=56 or not 1<=count<=1024 or off+count*56>len(raw):raise Blocked('EXECUTABLE_PROGRAM_HEADERS')
    interpreter=None;loads=0;executable=False;segments=[];dynamic=None
    for i in range(count):
        typ,flags,offset,vaddr,paddr,size,memsize,align=struct.unpack_from('<IIQQQQQQ',raw,off+i*56)
        if offset+size>len(raw) or (typ==1 and size>memsize):raise Blocked('EXECUTABLE_SEGMENT_BOUNDS')
        if typ==1:
            loads+=1;segments.append((vaddr,offset,size))
            if flags&1:executable=True
            if flags&1 and flags&2:raise Blocked('EXECUTABLE_WRITABLE_CODE')
        if typ==2:dynamic=(offset,size)
        if typ==3:
            if interpreter is not None:raise Blocked('EXECUTABLE_MULTIPLE_LOADERS')
            data=raw[offset:offset+size]
            if not data.endswith(b'\0') or b'\0' in data[:-1]:raise Blocked('EXECUTABLE_LOADER')
            try:interpreter=data[:-1].decode('ascii')
            except UnicodeError as exc:raise Blocked('EXECUTABLE_LOADER') from exc
            if not interpreter.startswith('/') or '..' in interpreter.split('/'):raise Blocked('EXECUTABLE_LOADER')
    if not loads or not executable:raise Blocked('EXECUTABLE_LOADABLE_CODE_MISSING')
    needed=[]
    if dynamic is not None:
        doff,dsize=dynamic;strings=None;string_size=None;indexes=[]
        if dsize%16:raise Blocked('EXECUTABLE_DYNAMIC_BOUNDS')
        for position in range(doff,doff+dsize,16):
            tag,value=struct.unpack_from('<qQ',raw,position)
            if tag==0:break
            if tag==1:indexes.append(value)
            if tag==5:strings=value
            if tag==10:string_size=value
        if indexes:
            matches=[offset+strings-vaddr for vaddr,offset,size in segments if strings is not None and vaddr<=strings<vaddr+size]
            if len(matches)!=1 or string_size is None or matches[0]+string_size>len(raw):raise Blocked('EXECUTABLE_DYNAMIC_STRINGS')
            table=raw[matches[0]:matches[0]+string_size]
            for index in indexes:
                end=table.find(b'\0',index)
                if index>=len(table) or end<0:raise Blocked('EXECUTABLE_DYNAMIC_DEPENDENCY')
                try:name=table[index:end].decode('ascii')
                except UnicodeError as exc:raise Blocked('EXECUTABLE_DYNAMIC_DEPENDENCY') from exc
                if not name or '/' in name:raise Blocked('EXECUTABLE_DYNAMIC_DEPENDENCY')
                needed.append(name)
    return {'architecture':'linux-x86_64','interpreter':interpreter,'load_segments':loads,'needed':needed}


def original_file(path, expected_sha256, *, maximum=512*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=maximum:raise Blocked('IMAGE_FILE_TYPE_OR_SIZE')
        chunks=[];offset=0
        while offset<before.st_size:
            chunk=os.pread(fd,min(1048576,before.st_size-offset),offset)
            if not chunk:raise Blocked('IMAGE_SHORT_READ')
            chunks.append(chunk);offset+=len(chunk)
        raw=b''.join(chunks);after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Blocked('IMAGE_CHANGED_DURING_READ')
        if hashlib.sha256(raw).hexdigest()!=expected_sha256:raise Blocked('IMAGE_DIGEST')
        return raw
    finally:os.close(fd)


def sealed_executable(path, expected_sha256, *, runtime_files):
    raw=original_file(path,expected_sha256);info=inspect_elf(raw)
    if type(runtime_files) is not dict:raise Blocked('EXECUTABLE_RUNTIME_MANIFEST')
    # PT_INTERP is opened by the kernel, not inherited as a verified FD. Require
    # the actual loader inode read-only as well as pinned. Hash alone is unsafe.
    for name,digest in runtime_files.items():
        dependency=original_file(name,digest)
        if dependency[:4]==b'\x7fELF':
            dep_info=inspect_elf(dependency)
            for required in dep_info['needed']:
                if sum(os.path.basename(path)==required for path in runtime_files)!=1:raise Blocked('EXECUTABLE_TRANSITIVE_DEPENDENCY_UNPINNED')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            if not os.fstatvfs(fd).f_flag&os.ST_RDONLY:raise Blocked('EXECUTABLE_RUNTIME_NOT_READONLY')
        finally:os.close(fd)
    if info['interpreter'] is not None and info['interpreter'] not in runtime_files:
        raise Blocked('EXECUTABLE_LOADER_UNPINNED')
    for required in info['needed']:
        if sum(os.path.basename(path)==required for path in runtime_files)!=1:raise Blocked('EXECUTABLE_DEPENDENCY_UNPINNED')
    fd=os.memfd_create('adamon-executable',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:])
            if n<=0:raise Blocked('EXECUTABLE_SEAL_WRITE')
            offset+=n
        fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
        return fd
    except BaseException:os.close(fd);raise
