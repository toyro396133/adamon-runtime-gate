"""Descriptor-bound Firecracker launcher inside an already prepared local jail.

No deployment/provisioning, workflow interface or research authorization. Native
supervisor owns namespace/cgroup/UID jail; this module refuses absent kernel KVM
and missing immutable launch capabilities. Paths/argv are fixed, not RPC input.
"""
from dataclasses import dataclass
import hashlib
import os
import socket
import struct
import subprocess
import time
import signal
from .microvm import Blocked, UnixHTTP
from .vsock import connect_guest


@dataclass(frozen=True)
class ImmutableFD:
    fd: int
    sha256: str

    def verify(self):
        if type(self.fd) is not int or self.fd<0 or type(self.sha256) is not str or len(self.sha256)!=64:
            raise Blocked('VMM_IMMUTABLE_DESCRIPTOR')
        # Read pinned open descriptor, preventing pathname replacement races.
        before=os.fstat(self.fd)
        if not os.path.isfile('/proc/self/fd/'+str(self.fd)):
            raise Blocked('VMM_DESCRIPTOR_NOT_REGULAR')
        h=hashlib.sha256(); offset=0
        while True:
            block=os.pread(self.fd,1024*1024,offset)
            if not block: break
            h.update(block); offset+=len(block)
        after=os.fstat(self.fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or h.hexdigest()!=self.sha256:
            raise Blocked('VMM_IMMUTABLE_DIGEST')
        # Sealed memfd or immutable readonly fs required, not just hash check.
        import fcntl
        try:
            seals=fcntl.fcntl(self.fd,getattr(fcntl,'F_GET_SEALS',1034))
            sealed=seals & (getattr(fcntl,'F_SEAL_WRITE',8)|getattr(fcntl,'F_SEAL_GROW',4)|getattr(fcntl,'F_SEAL_SHRINK',2))==(getattr(fcntl,'F_SEAL_WRITE',8)|getattr(fcntl,'F_SEAL_GROW',4)|getattr(fcntl,'F_SEAL_SHRINK',2))
        except OSError:
            readonly=bool(os.fstatvfs(self.fd).f_flag & os.ST_RDONLY)
            sealed=readonly
        if not sealed: raise Blocked('VMM_MUTABLE_SOURCE_DESCRIPTOR')


class LocalLauncher:
    """Launcher entered by trusted native factory after UID/ns/cgroup drop.

    Required jail root identity must be measured from trusted fixed manifest;
    caller passes open jail fd directly, never a guest/workflow pathname.
    This is PRE-CREDENTIAL birth only: native mutation guard denies clone/exec,
    so the trusted birth stage must invoke start BEFORE issuing Launcher keys
    and installing that guard. The native spawn helper itself does not install that guard; pinned Launcher
    init must call prepare() in exactly this order. Its deployable executable
    image and KVM execution remain absent/unverified.
    Bootstrap integration has not been exercised on KVM; public research entry
    remains blocked elsewhere and cannot obtain this object via an RPC.
    """
    def __init__(self, binary, jail_root_fd, expected_jail_device_inode, worker_pidfd):
        self.binary=binary; self.jail_fd=jail_root_fd
        self.expected_root=expected_jail_device_inode; self.worker_pidfd=worker_pidfd
        self.process=None
        self.prepared=False
        self.credential_fd=None

    @classmethod
    def from_owner_assets(cls,deployment,worker_pidfd):
        """Fixed native-jail filenames, verified against owner-signed authority.

        Pinned Launcher image calls this before guard/key delivery. No filename
        is accepted from Workflow, guest or RPC. Guest/VMM live use unverified.
        """
        pins=deployment.payload()['images']
        retained=[]
        try:
            for path,name in (('/firecracker','firecracker'),('/kernel','kernel'),('/rootfs','rootfs')):
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                retained.append(fd);ImmutableFD(fd,pins[name]).verify()
            jail=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            retained.append(jail);root=os.fstat(jail)
            value=cls(ImmutableFD(retained[0],pins['firecracker']),jail,(root.st_dev,root.st_ino),worker_pidfd)
            value.owner_assets=tuple(retained);value.deployment=deployment
            return value
        except BaseException:
            for fd in retained:os.close(fd)
            raise

    def close_owner_assets(self):
        if self.process is not None:raise Blocked('VMM_ASSETS_STILL_IN_USE')
        for fd in getattr(self,'owner_assets',()):os.close(fd)
        self.owner_assets=()

    def start(self):
        if self.process is not None: raise Blocked('VMM_ONE_SHOT')
        self.binary.verify()
        if hasattr(self,'deployment'):self.deployment.payload()
        root=os.stat('/')
        jail=os.fstat(self.jail_fd)
        if (root.st_dev,root.st_ino)!=(jail.st_dev,jail.st_ino) or (root.st_dev,root.st_ino)!=self.expected_root:
            raise Blocked('LAUNCHER_NOT_IN_TRUSTED_JAIL')
        if os.geteuid()==0: raise Blocked('VMM_PRIVILEGE_NOT_DROPPED')
        import select
        poll=select.poll(); poll.register(self.worker_pidfd,select.POLLIN)
        if poll.poll(0): raise Blocked('WORKER_NOT_LIVE')
        if not os.path.exists('/dev/kvm'): raise Blocked('LOCAL_KVM_MISSING')
        if os.path.lexists('/firecracker.socket') or os.path.lexists('/private-control.vsock'):
            raise Blocked('VMM_STALE_OR_SUBSTITUTED_SOCKET')
        # Kernel/root/evidence mounts and credentials are provisioned by native
        # supervisor BEFORE this launcher enters the jail. No shell/env fallback.
        self.process=subprocess.Popen(['firecracker','--api-sock','/firecracker.socket'],
            executable='/proc/self/fd/'+str(self.binary.fd),
            pass_fds=(self.binary.fd,), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'PATH':'/nonexistent'},close_fds=True)
        try:self.pidfd=os.pidfd_open(self.process.pid)
        except BaseException:
            # Child is still owned and unreaped: its PID cannot be reused.
            try:self.process.kill()
            finally:self.process.wait(timeout=10)
            self.process=None
            raise
        return self.pidfd

    def api(self):
        if self.process is None: raise Blocked('VMM_NOT_STARTED')
        stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            stream.connect('/firecracker.socket')
            pid,uid,_gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid!=self.process.pid or uid!=os.geteuid():
                raise Blocked('VMM_API_PEER_IDENTITY')
        except BaseException: stream.close(); raise
        return UnixHTTP(stream)

    def await_api(self, timeout=10, clock=time.monotonic):
        """Bound startup; never accept a stale peer or continue failed birth."""
        if type(timeout) not in (int,float) or not 0<timeout<=30:
            raise Blocked('VMM_STARTUP_TIMEOUT_BOUND')
        deadline=clock()+timeout
        try:
            while clock()<deadline:
                if self.process is None or self.process.poll() is not None:
                    raise Blocked('VMM_EARLY_EXIT')
                try:return self.api()
                except (FileNotFoundError,ConnectionRefusedError):
                    time.sleep(min(.02,max(0,deadline-clock())))
            raise Blocked('VMM_STARTUP_TIMEOUT')
        except BaseException:
            self.stop()
            raise

    def stop(self):
        """Signal original pidfd, reap owned child, never kill recycled PID."""
        if self.process is None:return
        try:
            signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
        except ProcessLookupError:pass
        finally:
            self.process.wait(timeout=10)
            os.close(self.pidfd)
            self.process=None

    def guest(self):
        if self.process is None: raise Blocked('VMM_NOT_STARTED')
        stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            stream.connect('/private-control.vsock')
            return connect_guest(stream)
        except BaseException: stream.close(); raise

    def prepare(self, native, credential_socket, expected_issuer_pid, expected_issuer_uid, expected_key_spki_sha256, expected_binding, issuer_ca_public_key, binding_oid):
        """Fixed birth -> irreversible syscall guard -> sealed key FD receive.

        Trusted native bootstrap supplies this already-connected local channel.
        No issuer identity, pathname or executable comes from a workflow/RPC.
        The returned key remains descriptor-only; no credential may be issued
        until broker independently attests this staged Launcher process/channel.
        This entry has NOT been exercised on privileged GitHub/KVM hardware.
        """
        if self.prepared: raise Blocked('LAUNCHER_ONE_SHOT')
        if credential_socket.family!=socket.AF_UNIX: raise Blocked('LOCAL_ISSUER_REQUIRED')
        peer_pid,peer_uid,_=struct.unpack('3i',credential_socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if (peer_pid,peer_uid)!=(expected_issuer_pid,expected_issuer_uid):
            raise Blocked('LAUNCHER_ISSUER_IDENTITY')
        pidfd=self.start()
        try:
            native.install_launcher_guard()
            # No clone/exec/mutation after this point. This launcher may only
            # drive inherited local VMM API/vsock and consume fixed credentials.
            credential_socket.settimeout(10)
            fd,certificate=receive_bootstrap(credential_socket,expected_key_spki_sha256,
                expected_binding,issuer_ca_public_key,binding_oid)
            self.credential_fd=fd; self.certificate=certificate; self.prepared=True
            return pidfd,fd
        except BaseException:
            import signal
            self.stop()
            raise


def receive_bootstrap(stream, expected_spki, expected_binding, issuer_ca_public_key, binding_oid):
    """Exact wire peer of security.supervisor.deliver_launcher_bootstrap()."""
    import array, fcntl, json
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from .guest import canonical
    received=[]
    try:
        head,ancillary,flags,_=stream.recvmsg(4,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_WAITALL|socket.MSG_CMSG_CLOEXEC)
        for level,kind,data in ancillary:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:
                raise Blocked('LAUNCHER_BOOTSTRAP_ANCILLARY')
            values=array.array('i');values.frombytes(data[:len(data)-len(data)%values.itemsize]);received.extend(values)
        if len(head)!=4 or flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) or len(received)!=1:
            raise Blocked('LAUNCHER_BOOTSTRAP_FRAME')
        length=struct.unpack('!I',head)[0]
        if not 0<length<=65536: raise Blocked('LAUNCHER_BOOTSTRAP_LIMIT')
        raw=bytearray()
        while len(raw)<length:
            chunk=stream.recv(length-len(raw))
            if not chunk: raise Blocked('LAUNCHER_BOOTSTRAP_TRUNCATED')
            raw.extend(chunk)
        def unique(pairs):
            out={}
            for k,v in pairs:
                if k in out: raise Blocked('LAUNCHER_BOOTSTRAP_DUPLICATE')
                out[k]=v
            return out
        body=json.loads(raw,object_pairs_hook=unique)
        if type(body) is not dict or set(body)!={'version','spki_sha256','binding','certificate_pem'} or type(body['version']) is not int or body['version']!=4:
            raise Blocked('LAUNCHER_BOOTSTRAP_SCHEMA')
        if canonical(body['binding'])!=canonical(expected_binding) or body['spki_sha256']!=expected_spki:
            raise Blocked('LAUNCHER_BOOTSTRAP_BINDING')
        cert=x509.load_pem_x509_certificate(body['certificate_pem'].encode('ascii'))
        Ed25519PublicKey.from_public_bytes(issuer_ca_public_key).verify(cert.signature,cert.tbs_certificate_bytes)
        from datetime import datetime,timezone
        now=datetime.now(timezone.utc)
        if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc:
            raise Blocked('LAUNCHER_BOOTSTRAP_CERT_EXPIRY')
        ext=cert.extensions.get_extension_for_oid(binding_oid)
        if not ext.critical or ext.value.value!=canonical(expected_binding):
            raise Blocked('LAUNCHER_BOOTSTRAP_CERT_BINDING')
        fd=received[0];seals=fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))
        if os.fstat(fd).st_size!=32 or seals&15!=15:
            raise Blocked('LAUNCHER_CREDENTIAL_NOT_SEALED')
        key=Ed25519PrivateKey.from_private_bytes(os.pread(fd,32,0))
        actual=key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        certificate_spki=cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        if actual!=certificate_spki or hashlib.sha256(actual).hexdigest()!=expected_spki:
            raise Blocked('LAUNCHER_CREDENTIAL_SPKI_BINDING')
        os.set_inheritable(fd,False);received=[]
        return fd,cert
    finally:
        for fd in received: os.close(fd)
