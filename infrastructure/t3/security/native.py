"""Bindings to separately hashed native library; does not authorize launch."""
import ctypes
import hashlib
from .protocol import Denied

class Child(ctypes.Structure):
    _fields_=[('pid',ctypes.c_int),('pidfd',ctypes.c_int),('resume_fd',ctypes.c_int),('error_fd',ctypes.c_int)]

class Native:
    def __init__(self, library_path, expected_sha256):
        import os,fcntl
        with open(library_path,'rb') as f:
            library=f.read(16*1024*1024+1)
        if len(library)>16*1024*1024 or hashlib.sha256(library).hexdigest()!=expected_sha256:
            raise Denied('native binary digest/size')
        # Load exactly the verified bytes from an immutable sealed inode. A
        # pathname swap between hash and dlopen cannot select different code.
        fd=os.memfd_create('p4-verified-native',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            view=memoryview(library)
            while view:
                n=os.write(fd,view)
                if n<=0:raise Denied('native image write')
                view=view[n:]
            # Linux uapi fcntl.h constants; some Python builds omit names.
            fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
            self.lib=ctypes.CDLL('/proc/self/fd/'+str(fd),use_errno=True)
        finally:os.close(fd)
        self.lib.p4_sealed_key_memfd.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        self.lib.p4_sealed_key_memfd.restype=ctypes.c_int
        self.lib.p4_spawn_paused.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_int,ctypes.POINTER(Child)]
        self.lib.p4_spawn_paused.restype=ctypes.c_int
        self.lib.p4_spawn_role_paused.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.POINTER(Child)]
        self.lib.p4_spawn_role_paused.restype=ctypes.c_int
        self.lib.p4_resume.argtypes=[ctypes.POINTER(Child)]
        self.lib.p4_resume.restype=ctypes.c_int
        self.lib.p4_exec_ack.argtypes=[ctypes.POINTER(Child)]
        self.lib.p4_exec_ack.restype=ctypes.c_int
    def install_launcher_guard(self):
        """Called by Launcher only AFTER VMM birth and BEFORE key receipt."""
        if self.lib.p4_launcher_mutation_guard()<0:
            raise OSError(ctypes.get_errno(),'launcher immutable mutation guard')
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

class NativeProcessFactory:
    """Owner-fixed native birth factory, never a caller-supplied PID or argv.

    Each role must have a separately provisioned immutable executable and UID.
    Actual clone3/cgroup/namespace execution still requires privileged preflight.
    This capability does not authorize a research launch.
    """
    def __init__(self, native, roles, *, exec_timeout=10):
        if type(exec_timeout) not in (int,float) or not 0 < exec_timeout <= 30:
            raise Denied('bounded exec timeout required')
        if set(roles) != {'LISTENER','WORKER','LAUNCHER'}:
            raise Denied('three closed native roles required')
        self.native,self.roles,self.timeout=native,{k:dict(v) for k,v in roles.items()},exec_timeout
        if len({r['uid'] for r in roles.values()}) != 3:
            raise Denied('separate role UIDs required')
        for spec in self.roles.values():
            if set(spec) != {'exe_fd','sha256','cgroup_fd','cgroup','uid','gid'}:
                raise Denied('native role configuration shape')
            if type(spec['uid']) is not int or type(spec['gid']) is not int or min(spec['uid'],spec['gid'])<=0:
                raise Denied('non-root role identity required')

    def spawn(self, role, bootstrap_fd, *, channel_in=-1,channel_out=-1):
        import os, select, signal
        from .process import ProcessRecord
        if role not in self.roles: raise Denied('unknown native role')
        spec=self.roles[role]
        # pread never moves a descriptor shared with another child.
        digest=hashlib.sha256(); offset=0
        while True:
            data=os.pread(spec['exe_fd'],1024*1024,offset)
            if not data: break
            digest.update(data);offset+=len(data)
        if digest.hexdigest()!=spec['sha256']: raise Denied('native executable pin')
        child=self.native.spawn_role_candidate(role,spec['exe_fd'],spec['cgroup_fd'],spec['uid'],spec['gid'],bootstrap_fd,channel_in,channel_out)
        try:
            if self.native.lib.p4_resume(ctypes.byref(child))<0:
                raise OSError(ctypes.get_errno(),'native resume')
            poll=select.poll();poll.register(child.error_fd,select.POLLIN|select.POLLHUP)
            if not poll.poll(int(self.timeout*1000)): raise Denied('native exec timeout')
            if self.native.lib.p4_exec_ack(ctypes.byref(child))<0:
                raise OSError(ctypes.get_errno(),'native exec failed')
            with open(f'/proc/{child.pid}/stat') as f: stat=f.read()
            ticks=int(stat[stat.rfind(')')+2:].split()[19])
            record=ProcessRecord(child.pid,child.pidfd,spec['uid'],ticks,spec['cgroup'],spec['sha256'])
            record.verify()
            return record
        except BaseException:
            try: signal.pidfd_send_signal(child.pidfd,signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitid(os.P_PIDFD,child.pidfd,os.WEXITED)
            finally: os.close(child.pidfd)
            raise
        finally:
            for fd in (child.resume_fd,child.error_fd):
                if fd>=0: os.close(fd)
