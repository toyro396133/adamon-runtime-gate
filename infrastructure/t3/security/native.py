"""Bindings to separately hashed native library; does not authorize launch."""
import ctypes
import hashlib
from .protocol import Denied

class Child(ctypes.Structure):
    _fields_=[('pid',ctypes.c_int),('pidfd',ctypes.c_int),('resume_fd',ctypes.c_int),('error_fd',ctypes.c_int)]

class Native:
    def __init__(self, library_path, expected_sha256):
        with open(library_path,'rb') as f:
            if hashlib.file_digest(f,'sha256').hexdigest()!=expected_sha256: raise Denied('native binary digest')
        # Caller path must be supervisor-owned immutable; digest alone is not an
        # anti-TOCTOU inode proof, hence this object cannot grant research starts.
        self.lib=ctypes.CDLL(library_path,use_errno=True)
        self.lib.p4_sealed_key_memfd.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        self.lib.p4_sealed_key_memfd.restype=ctypes.c_int
        self.lib.p4_spawn_paused.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_int,ctypes.POINTER(Child)]
        self.lib.p4_spawn_paused.restype=ctypes.c_int
        self.lib.p4_spawn_role_paused.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.POINTER(Child)]
        self.lib.p4_spawn_role_paused.restype=ctypes.c_int
    def spawn_role_candidate(self, role, exe_fd, cgroup_fd, uid, gid, bootstrap_fd, channel_in=-1, channel_out=-1):
        if role not in {'LISTENER','WORKER','LAUNCHER'}: raise Denied('closed native role')
        child=Child()
        number={'LISTENER':1,'WORKER':2,'LAUNCHER':3}[role]
        if self.lib.p4_spawn_role_paused(exe_fd,cgroup_fd,uid,gid,bootstrap_fd,number,channel_in,channel_out,ctypes.byref(child))<0:
            raise OSError(ctypes.get_errno(),'isolated role spawn')
        return child
    def sealed_key(self, key_bytes):
        if len(key_bytes)!=32: raise Denied('key size')
        buf=ctypes.create_string_buffer(key_bytes)
        try:
            fd=self.lib.p4_sealed_key_memfd(buf,32)
            if fd<0: raise OSError(ctypes.get_errno(),'sealed memfd')
            return fd
        finally: ctypes.memset(buf,0,len(buf))
    def spawn_candidate(self, exe_fd,cgroup_fd,uid,gid,bootstrap_fd):
        child=Child()
        if self.lib.p4_spawn_paused(exe_fd,cgroup_fd,uid,gid,bootstrap_fd,ctypes.byref(child))<0:
            raise OSError(ctypes.get_errno(),'clone3 immutable isolated spawn')
        return child
