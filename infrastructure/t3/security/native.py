"""Bindings to separately hashed native library; does not authorize launch."""
import ctypes
import hashlib
from types import MappingProxyType
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
    def provision_jail(self, jail_fd, source_fd, fixture_fd, evidence_fd, parent_mount_inode, parent_net_inode):
        """Child pre-credential provisioning in already fresh mount/net namespaces.

        No path or network URL is accepted. Caller must discard the namespace on
        failure, before UID drop or issuance. Privileged live use is unverified.
        """
        fn=self.lib.p4_provision_jail
        fn.argtypes=[ctypes.c_int]*4+[ctypes.c_ulong]*2
        fn.restype=ctypes.c_int
        if fn(jail_fd,source_fd,fixture_fd,evidence_fd,parent_mount_inode,parent_net_inode)<0:
            raise OSError(ctypes.get_errno(),'closed jail namespace provisioning')

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
    def spawn_launcher_jail_candidate(self, exe_fd, cgroup_fd, uid, gid, bootstrap_fd, jail_fd, source_fd, fixture_fd, evidence_fd, parent_mount_inode, parent_net_inode):
        """clone3 pidfd → paused → fresh namespaces/jail → dropUID → exactexec.

        Provisioning occurs inside child before inherited descriptors are closed.
        No key is delivered by this operation. Privileged preflight is required.
        """
        fn=self.lib.p4_spawn_launcher_jail_paused
        fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint]+[ctypes.c_int]*5+[ctypes.c_ulong]*2+[ctypes.POINTER(Child)]
        fn.restype=ctypes.c_int
        child=Child()
        if fn(exe_fd,cgroup_fd,uid,gid,bootstrap_fd,jail_fd,source_fd,fixture_fd,evidence_fd,parent_mount_inode,parent_net_inode,ctypes.byref(child))<0:
            raise OSError(ctypes.get_errno(),'isolated jailed launcher spawn')
        return child

    def spawn_launcher_vm_candidate(self,exe_fd,cgroup_fd,uid,gid,bootstrap_fd,jail_fd,source_fd,fixture_fd,evidence_fd,parent_mount_inode,parent_net_inode,firecracker_fd,kernel_fd,rootfs_fd,kvm_fd,volume_fd,volume_readonly,worker_pidfd):
        fn=self.lib.p4_spawn_launcher_vm_paused
        fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint]+[ctypes.c_int]*5+[ctypes.c_ulong]*2+[ctypes.c_int]*7+[ctypes.POINTER(Child)]
        fn.restype=ctypes.c_int
        child=Child()
        if fn(exe_fd,cgroup_fd,uid,gid,bootstrap_fd,jail_fd,source_fd,fixture_fd,evidence_fd,parent_mount_inode,parent_net_inode,firecracker_fd,kernel_fd,rootfs_fd,kvm_fd,volume_fd,int(volume_readonly),worker_pidfd,ctypes.byref(child))<0:
            raise OSError(ctypes.get_errno(),'isolated pinned VM launcher birth')
        return child

    def spawn_listener_network_candidate(self,exe_fd,cgroup_fd,uid,gid,bootstrap_fd,network_fd):
        fn=self.lib.p4_spawn_listener_network_paused
        fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.c_uint,ctypes.c_int,ctypes.c_int,ctypes.POINTER(Child)]
        fn.restype=ctypes.c_int;child=Child()
        if fn(exe_fd,cgroup_fd,uid,gid,bootstrap_fd,network_fd,ctypes.byref(child))<0:
            raise OSError(ctypes.get_errno(),'owner restricted Listener network birth')
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
    def __init__(self, native, roles, *, exec_timeout=10, launcher_jail=None, vm_assets=None, evidence_volume=None, listener_network=None):
        if type(exec_timeout) not in (int,float) or not 0 < exec_timeout <= 30:
            raise Denied('bounded exec timeout required')
        if set(roles) != {'LISTENER','WORKER','LAUNCHER'}:
            raise Denied('three closed native roles required')
        self.native,self.roles,self.timeout=native,MappingProxyType({k:MappingProxyType(dict(v)) for k,v in roles.items()}),exec_timeout
        if launcher_jail is not None:
            from ..runtime.deployment import JailDescriptors
            if not isinstance(launcher_jail,JailDescriptors):raise Denied('typed owner launcher jail required')
        self.launcher_jail=launcher_jail
        if vm_assets is not None:
            from ..runtime.deployment import VMAssetDescriptors
            if not isinstance(vm_assets,VMAssetDescriptors) or launcher_jail is None:raise Denied('typed jailed VM assets required')
        self.vm_assets=vm_assets
        if evidence_volume is not None:
            from ..runtime.deployment import EvidenceVolume
            if not isinstance(evidence_volume,EvidenceVolume) or vm_assets is None:raise Denied('typed VM evidence volume required')
        if listener_network is not None:
            from ..runtime.deployment import ListenerNetwork
            if not isinstance(listener_network,ListenerNetwork):raise Denied('typed listener namespace required')
        self.evidence_volume=evidence_volume;self.listener_network=listener_network;self._worker=None
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
        if role=='LISTENER' and self.listener_network is not None:
            child=self.native.spawn_listener_network_candidate(spec['exe_fd'],spec['cgroup_fd'],spec['uid'],spec['gid'],bootstrap_fd,self.listener_network.fd)
        elif role=='LAUNCHER' and self.launcher_jail is not None:
            j=self.launcher_jail
            args=(spec['exe_fd'],spec['cgroup_fd'],spec['uid'],spec['gid'],bootstrap_fd,j.jail_fd,j.source_fd,j.fixture_fd,j.evidence_fd,j.parent_mount_inode,j.parent_net_inode)
            if self.vm_assets is not None:
                v=self.vm_assets
                if self.evidence_volume is None:raise Denied('VM evidence volume missing')
                volume=self.evidence_volume
                # Bind mounts retain original inode permissions. Refuse before
                # birth instead of chmod'ing private evidence/host KVM device.
                def required_access(fd,required):
                    st=os.fstat(fd)
                    bits=(st.st_mode>>6)&7 if st.st_uid==spec['uid'] else (st.st_mode>>3)&7 if st.st_gid==spec['gid'] else st.st_mode&7
                    if bits&required!=required:raise Denied('mounted VMM asset inaccessible to isolated UID/GID')
                required_access(v.kvm_fd,6)
                required_access(volume.fd,4 if volume.read_only else 6)
                required_access(v.firecracker_fd,5)
                required_access(v.kernel_fd,4);required_access(v.rootfs_fd,4)
                if self._worker is None:raise Denied('enrolled Worker pidfd missing for Launcher birth')
                self._worker.verify()
                child=self.native.spawn_launcher_vm_candidate(*args,v.firecracker_fd,v.kernel_fd,v.rootfs_fd,v.kvm_fd,volume.fd,volume.read_only,self._worker.pidfd)
            else:child=self.native.spawn_launcher_jail_candidate(*args)
        else:
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
            if role=='WORKER':self._worker=record
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
