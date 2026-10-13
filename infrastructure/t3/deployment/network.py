"""Owner-only network namespace birth. No host network fallback or shell.

A fresh Linux network namespace has only a DOWN loopback interface and no
routes. Control traffic uses inherited, owner-authenticated AF_UNIX capabilities,
never an IP interface. No privileged provisioning is performed on import.
"""
import ctypes
import fcntl
import hashlib
import json
import os
import select
import signal
import socket
import threading
import time
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..runtime.guest import canonical
from ..runtime.microvm import Blocked
from ..runtime.deployment import ListenerNetwork

DOMAIN=b'ADAMON-T3-NETWORK-POLICY-V1\0'
CHANNELS={'LISTENER':['assignment','identity'], 'WORKER':['assignment'],
          'LAUNCHER':['bootstrap','evidence'], 'WATCHDOG':['lifecycle'],
          'STORAGE':['evidence']}

@dataclass(frozen=True)
class NetworkPolicy:
    raw: bytes
    clock: object
    @classmethod
    def verify(cls,envelope,owner_public_key,clock=time.time):
        if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:
            raise Blocked('NETWORK_POLICY_ENVELOPE')
        p=envelope['payload']
        if type(p) is not dict or set(p)!={'version','job_binding_sha256','channels','network','expires_at'}:
            raise Blocked('NETWORK_POLICY_SCHEMA')
        import re
        if type(p['version']) is not int or p['version']!=1 or type(p['job_binding_sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',p['job_binding_sha256']):raise Blocked('NETWORK_POLICY_BINDING')
        if p['channels']!=CHANNELS or p['network'] not in {'NO_INTERFACES_NO_ROUTES_LOOPBACK_DOWN','LISTENER_FIXED_CONNECT_LOOPBACK_ONLY'}:raise Blocked('NETWORK_POLICY_EGRESS')
        if type(p['expires_at']) is not int or not clock()<p['expires_at']:raise Blocked('NETWORK_POLICY_EXPIRED')
        raw=canonical(p)
        try:Ed25519PublicKey.from_public_bytes(owner_public_key).verify(bytes.fromhex(envelope['signature_hex']),DOMAIN+raw)
        except Exception as exc:raise Blocked('NETWORK_POLICY_SIGNATURE') from exc
        return cls(raw,clock)
    @property
    def sha256(self):return hashlib.sha256(self.raw).hexdigest()
    def require(self,binding):
        p=json.loads(self.raw)
        if not self.clock()<p['expires_at']:raise Blocked('NETWORK_POLICY_EXPIRED')
        if binding!=p['job_binding_sha256']:raise Blocked('NETWORK_POLICY_BINDING')

class LinuxNamespaceBackend:
    """Fork a root-owned holder; unshare happens before namespace FD publication.

    The private socket is the only inherited capability retained by the holder.
    Parent death closes it; poll/HUP terminates holder and namespace. The parent
    owns a pidfd and never signals a recycled numeric PID.
    """
    def __init__(self,listener=False):
        self.listener=listener
    def create(self):
        if os.geteuid()!=0:raise Blocked('NETWORK_OWNER_UID')
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
        pid=os.fork()
        if pid==0:
            try:
                parent.close()
                keep=child.fileno()
                for entry in os.listdir('/proc/self/fd'):
                    fd=int(entry)
                    if fd!=keep:
                        try:os.close(fd)
                        except OSError:pass
                libc=ctypes.CDLL(None,use_errno=True)
                if libc.unshare(0x40000000)!=0:raise OSError(ctypes.get_errno(),'unshare(CLONE_NEWNET)')
                fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
                def ready():
                    child.sendmsg([b'namespace'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,__import__('array').array('i',[fd]))])
                    os.close(fd)
                if self.listener:
                    from .network_proxy import listener_loopback_server
                    listener_loopback_server(child,ready)
                else:
                    ready()
                    while child.recv(1):pass
                os._exit(0)
            except BaseException:os._exit(127)
        child.close()
        pidfd=os.pidfd_open(pid,0)
        try:
            parent.settimeout(5)
            data,anc,flags,_=parent.recvmsg(32,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
            fds=[]
            for level,kind,value in anc:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    a=__import__('array').array('i');a.frombytes(value[:len(value)//4*4]);fds.extend(a)
            if data!=b'namespace' or flags&socket.MSG_CTRUNC or len(fds)!=1:
                for fd in fds:os.close(fd)
                raise Blocked('NETWORK_NAMESPACE_BIRTH')
            parent.settimeout(None)
            return pid,pidfd,parent,fds[0]
        except BaseException:
            parent.close()
            try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0);os.close(pidfd)
            raise
    def validate(self,pid,pidfd,fd):
        if select.select([pidfd],[],[],0)[0]:raise Blocked('NETWORK_HOLDER_DEAD')
        if fcntl.ioctl(fd,0xb703)!=0x40000000:raise Blocked('NETWORK_NAMESPACE_TYPE')
        if os.fstat(fd).st_ino==os.stat('/proc/self/ns/net').st_ino:raise Blocked('NETWORK_HOST_NAMESPACE')
        if os.stat(f'/proc/{pid}/ns/net').st_ino!=os.fstat(fd).st_ino:raise Blocked('NETWORK_NAMESPACE_IDENTITY')
        with open(f'/proc/{pid}/net/dev') as f:interfaces=[x.split(':')[0].strip() for x in f.read().splitlines()[2:] if ':' in x]
        if interfaces!=['lo']:raise Blocked('NETWORK_UNAUTHORIZED_INTERFACE')
        with open(f'/proc/{pid}/net/route') as f:
            if f.read().splitlines()[1:]:raise Blocked('NETWORK_UNAUTHORIZED_ROUTE')
        with open(f'/proc/{pid}/net/ipv6_route') as f:
            if f.read().strip():raise Blocked('NETWORK_UNAUTHORIZED_IPV6_ROUTE')
        # Fresh loopback flags must lack IFF_UP. Inspect in the holder namespace.
        with open(f'/proc/{pid}/net/if_inet6') as f:
            if f.read().strip():raise Blocked('NETWORK_IPV6_ADDRESS')
        if select.select([pidfd],[],[],0)[0]:raise Blocked('NETWORK_HOLDER_DEAD')
    def close(self,pid,pidfd,sock,fd):
        sock.close();os.close(fd)
        try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
        except ProcessLookupError:pass
        try:os.waitpid(pid,0)
        except ChildProcessError:pass
        os.close(pidfd)

class OwnerNetworkScope:
    def __init__(self,policy,binding,backend=None):
        if not isinstance(policy,NetworkPolicy):raise Blocked('NETWORK_VERIFIED_POLICY_REQUIRED')
        policy.require(binding)
        self.policy=policy;self.binding=binding;self.backend=backend or LinuxNamespaceBackend(listener=json.loads(policy.raw)['network']=='LISTENER_FIXED_CONNECT_LOOPBACK_ONLY')
        self._lock=threading.RLock();self._cancelled=False;self._resource=None
    @classmethod
    def adopt(cls,policy,binding,*,holder_pid,holder_pidfd,control_fd,namespace_fd):
        """Adopt signed owner-provisioned capabilities into service lifecycle.

        All descriptors are duplicated: successful adoption owns its copies;
        callers retain theirs. An invalid descriptor never authorizes a kill.
        Numeric PID is corroborated by the retained pidfd before /proc reads.
        """
        if os.geteuid()!=0:raise Blocked('NETWORK_OWNER_UID')
        if type(holder_pid) is not int or holder_pid<=0 or holder_pid==os.getpid():raise Blocked('NETWORK_HOLDER_IDENTITY')
        scope=cls(policy,binding)
        duplicates=[];control=None
        try:
            for fd in (holder_pidfd,control_fd,namespace_fd):
                if type(fd) is not int or fd<0:raise Blocked('NETWORK_ADOPT_DESCRIPTOR')
                duplicate=os.dup(fd);os.set_inheritable(duplicate,False);duplicates.append(duplicate)
            pidfd,channel_fd,netfd=duplicates
            control=socket.socket(fileno=channel_fd)
            if control.family!=socket.AF_UNIX or control.type!=socket.SOCK_SEQPACKET:raise Blocked('NETWORK_ADOPT_CONTROL_CHANNEL')
            import struct
            _,uid,_=struct.unpack('3i',control.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=0:raise Blocked('NETWORK_ADOPT_CONTROL_OWNER')
            with open('/proc/self/fdinfo/'+str(pidfd)) as f:
                fields=dict(line.strip().split(':',1) for line in f if ':' in line)
            if fields.get('Pid','').strip()!=str(holder_pid):raise Blocked('NETWORK_ADOPT_PIDFD_IDENTITY')
            with open('/proc/'+str(holder_pid)+'/status') as f:
                status=dict(line.strip().split(':',1) for line in f if ':' in line)
            if status.get('Uid','').split()!=['0']*4:raise Blocked('NETWORK_ADOPT_HOLDER_OWNER')
            scope.backend.validate(holder_pid,pidfd,netfd)
            scope._resource=(holder_pid,pidfd,control,netfd)
            return scope
        except BaseException:
            if control is not None:
                control.close()
            for i,fd in enumerate(duplicates):
                if i!=1 or control is None:
                    try:os.close(fd)
                    except OSError:pass
            raise
    def start(self):
        with self._lock:
            if self._cancelled or self._resource is not None:raise Blocked('NETWORK_SCOPE_STATE')
            self.policy.require(self.binding)
            resource=self.backend.create()
            try:self.backend.validate(resource[0],resource[1],resource[3])
            except BaseException:self.backend.close(*resource);raise
            self._resource=resource
            return self
    def listener(self,deployment):
        with self._lock:
            if self._cancelled or self._resource is None:raise Blocked('NETWORK_SCOPE_STATE')
            self.policy.require(self.binding)
            if deployment.payload()['listener_network']['policy_sha256']!=self.policy.sha256:raise Blocked('NETWORK_POLICY_DEPLOYMENT_PIN')
            r=self._resource;self.backend.validate(r[0],r[1],r[3])
            return ListenerNetwork(r[3]).verify(deployment)
    def control_channel(self):
        with self._lock:
            if self._cancelled or self._resource is None:raise Blocked('NETWORK_SCOPE_STATE')
            self.policy.require(self.binding)
            if json.loads(self.policy.raw)['network']!='LISTENER_FIXED_CONNECT_LOOPBACK_ONLY':
                raise Blocked('NETWORK_LISTENER_POLICY_REQUIRED')
            self.backend.validate(self._resource[0],self._resource[1],self._resource[3])
            return self._resource[2]
    def close(self):
        with self._lock:
            self._cancelled=True
            r=self._resource;self._resource=None
            if r is not None:self.backend.close(*r)
    def __enter__(self):return self.start()
    def __exit__(self,*_):self.close()

@dataclass(frozen=True)
class OwnerChannel:
    """Owner-vetted AF_UNIX channel; authentication remains protocol-specific.

    This check restricts FD inheritance and kernel peer identity. It deliberately
    does not substitute peer UID for signed Assignment/mTLS/permit validation.
    """
    fd:int
    role:str
    name:str
    owner_uid:int
    def verify(self,policy,binding):
        import struct
        policy.require(binding)
        if self.role not in CHANNELS or self.name not in CHANNELS[self.role]:raise Blocked('NETWORK_CHANNEL_ROLE')
        if type(self.fd) is not int or self.fd<0 or type(self.owner_uid) is not int or self.owner_uid<0:raise Blocked('NETWORK_CHANNEL_DESCRIPTOR')
        duplicate=os.dup(self.fd)
        try:
            sock=socket.socket(fileno=duplicate);duplicate=None
            try:
                if sock.family!=socket.AF_UNIX or sock.type not in (socket.SOCK_STREAM,socket.SOCK_SEQPACKET):raise Blocked('NETWORK_CHANNEL_FAMILY')
                pid,uid,gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=self.owner_uid or pid<=0:raise Blocked('NETWORK_CHANNEL_PEER')
            finally:sock.close()
        finally:
            if duplicate is not None:os.close(duplicate)
        os.set_inheritable(self.fd,False)
        return self
