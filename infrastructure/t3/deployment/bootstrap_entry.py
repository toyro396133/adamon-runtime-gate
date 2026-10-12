"""Fixed owner/launcher entrypoints. Bootstrap is an owner-created FD, not argv.

The signing public key and embedded module tree belong to the read-only image.
SCM_RIGHTS capabilities are accepted only from UID 0 on the inherited channel.
No request can select code, a command, a pathname, or a research subject.
"""
import array
import fcntl
import os
import socket
import struct
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..security.protocol import Denied,canonical,decode,verify,sign
from ..runtime.deployment import Deployment,IMAGES,JailDescriptors,VMAssetDescriptors,EvidenceVolume,ListenerNetwork
from ..runtime.microvm import Resources
from ..security.native import Native,NativeProcessFactory
from .service import OwnerDeploymentService
from .executable_image import inspect_elf
from .launcher_entry import run_owner_nonresearch_launcher
from .nonresearch_images import SUBJECT
DOMAIN='ADAMON-OWNER-EXECUTABLE-BOOTSTRAP-V1'
OWNER_FDS=frozenset({'native','cancel','broker','jail','source_dir','fixture_dir','evidence_dir','firecracker','kernel','rootfs','kvm','volume','listener_net','network_holder_pidfd','network_control'}|{'image_'+x for x in IMAGES}|{'exe_'+x for x in ('LISTENER','WORKER','LAUNCHER')}|{'cgroup_'+x for x in ('LISTENER','WORKER','LAUNCHER')})
LAUNCHER_FDS=frozenset({'native','signer','job_kill','subject_kill','broker'})


def send_bootstrap(channel,payload,descriptors,owner_key):
    """Supervisor-only one packet; descriptor names are signed and ordered."""
    names=sorted(descriptors)
    value=dict(payload,fd_names=names)
    raw=canonical(sign(value,owner_key,'owner',DOMAIN))
    if len(raw)>65536:raise Denied('bootstrap packet bound')
    if channel.type!=socket.SOCK_SEQPACKET:raise Denied('bootstrap seqpacket required')
    sent=channel.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[descriptors[n] for n in names]))])
    if sent!=len(raw):raise Denied('bootstrap send incomplete')


def receive_bootstrap(channel,owner_public_key,role):
    received=[]
    try:
        if channel.type!=socket.SOCK_SEQPACKET:raise Denied('bootstrap seqpacket required')
        _,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise Denied('bootstrap peer is not owner')
        raw,anc,flags,_=channel.recvmsg(65537,socket.CMSG_SPACE(64*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
        for level,kind,data in anc:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise Denied('bootstrap ancillary type')
            ints=array.array('i');ints.frombytes(data[:len(data)-len(data)%ints.itemsize]);received.extend(ints)
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(raw)>65536:raise Denied('bootstrap packet truncated')
        p=verify(decode(raw),{'owner':Ed25519PublicKey.from_public_bytes(owner_public_key)},DOMAIN)
        common={'version','role','expires_at','fd_names','deployment','native_sha256','deadline_seconds'}
        expected=common|({'repository','approved_identity','roles','jail','volume','network'} if role=='OWNER' else {'delegation','binding','resources'})
        if type(p) is not dict or set(p)!=expected or type(p['version']) is not int or p['version']!=1 or p['role']!=role:raise Denied('bootstrap closed schema')
        if type(p['expires_at']) is not int or not time.time()<p['expires_at']<=time.time()+300:raise Denied('bootstrap expired')
        if type(p['deadline_seconds']) is not int or not 1<=p['deadline_seconds']<=72*3600:raise Denied('bootstrap deadline')
        names=p['fd_names'];required=OWNER_FDS if role=='OWNER' else LAUNCHER_FDS
        if type(names) is not list or names!=sorted(required) or len(received)!=len(names):raise Denied('bootstrap descriptor set')
        fds=dict(zip(names,received))
        for fd in received:os.set_inheritable(fd,False)
        Deployment.verify(p['deployment'],owner_public_key,time.time)
        return p,fds
    except BaseException:
        for fd in received:os.close(fd)
        raise


class BrokerCapabilities:
    """Private owner channel: fixed methods, not shell/path RPC."""
    def __init__(self,fd):self.channel=socket.socket(fileno=os.dup(fd));self.channel.settimeout(30)
    def _call(self,operation,argument=None):
        allowed={'credential.revoke','credential.revoke_all','credential.token','credential.canary_live','evidence.partial','evidence.original','evidence.seal'}
        if operation not in allowed:raise Denied('closed broker operation')
        self.channel.sendall(struct.pack('!I',len(raw:=canonical({'operation':operation,'argument':argument})))+raw)
        def read(n):
            chunks=[]
            while n:
                part=self.channel.recv(n)
                if not part:raise Denied('owner broker EOF')
                chunks.append(part);n-=len(part)
            return b''.join(chunks)
        size=struct.unpack('!I',read(4))[0]
        if not 0<size<=65536:raise Denied('owner broker response bound')
        p=decode(read(size))
        if type(p) is not dict or set(p)!={'ok','result'} or p['ok'] is not True:raise Denied('owner broker refusal')
        return p['result']
    def revoke(self):return self._call('credential.revoke')
    def revoke_all(self):return self._call('credential.revoke_all')
    def preserve_partial(self,reason):return self._call('evidence.partial',reason)
    def seal_complete(self):return self._call('evidence.seal')
    def preserve_authenticated_original(self,raw,completion):
        if type(raw) is not bytes or len(raw)>16*1024*1024:raise Denied('original artifact bound')
        return self._call('evidence.original',{'artifact_hex':raw.hex(),'completion':completion})
    def token(self):
        value=self._call('credential.token')
        if type(value) is not str or not value:raise Denied('owner GitHub token missing')
        return value
    def check_live(self,role,subject):
        if (role,subject)!=('LIFE',SUBJECT):return False
        return self._call('credential.canary_live',{'role':role,'subject':subject}) is True


def assemble_owner(p,fds,key):
    deployment=Deployment.verify(p['deployment'],key,time.time)
    roles=p['roles']
    if type(roles) is not dict or set(roles)!={'LISTENER','WORKER','LAUNCHER'}:raise Denied('bootstrap role set')
    specs={}
    authority=deployment.payload()
    for role,spec in roles.items():
        if type(spec) is not dict or set(spec)!={'cgroup'} or type(spec['cgroup']) is not str or not spec['cgroup'].startswith('0::/'):raise Denied('bootstrap cgroup schema')
        inspect_elf(os.pread(fds['exe_'+role],os.fstat(fds['exe_'+role]).st_size,0))
        specs[role]=dict(spec,exe_fd=fds['exe_'+role],cgroup_fd=fds['cgroup_'+role],sha256=authority['process_executables'][role],**authority['identities'][role])
    if type(p['jail']) is not dict or set(p['jail'])!={'parent_mount_inode','parent_net_inode'}:raise Denied('bootstrap jail schema')
    jail=JailDescriptors(fds['jail'],fds['source_dir'],fds['fixture_dir'],fds['evidence_dir'],**p['jail'])
    volume=EvidenceVolume.verify(fds['volume'],p['volume'],key,time.time)
    network=p['network']
    if type(network) is not dict or set(network)!={'policy','binding_sha256','holder_pid'}:raise Denied('bootstrap network schema')
    import hashlib
    if network['binding_sha256']!=hashlib.sha256(canonical(p['approved_identity'])).hexdigest():raise Denied('bootstrap network identity binding')
    from .network import NetworkPolicy,OwnerNetworkScope
    policy=NetworkPolicy.verify(network['policy'],key,time.time)
    network_scope=OwnerNetworkScope.adopt(policy,network['binding_sha256'],holder_pid=network['holder_pid'],holder_pidfd=fds['network_holder_pidfd'],control_fd=fds['network_control'],namespace_fd=fds['listener_net'])
    try:
        network_scope.listener(deployment)
    except BaseException:network_scope.close();raise
    try:
        native=Native('/proc/self/fd/'+str(fds['native']),p['native_sha256'])
        factory=NativeProcessFactory(native,specs,launcher_jail=jail,vm_assets=VMAssetDescriptors(*(fds[x] for x in ('firecracker','kernel','rootfs','kvm'))),evidence_volume=volume,listener_network=ListenerNetwork(fds['listener_net']))
        broker=BrokerCapabilities(fds['broker'])
        return OwnerDeploymentService(native_factory=factory,deployment_envelope=p['deployment'],owner_public_key=key,image_descriptors={x:fds['image_'+x] for x in IMAGES},repository=p['repository'],token_provider=broker.token,approved_identity=p['approved_identity'],credential_scope=broker,evidence_scope=broker,network_scope=network_scope)
    except BaseException:
        network_scope.close()
        raise


def assemble_launcher(p,fds,key):
    broker=BrokerCapabilities(fds['broker'])
    native=Native('/proc/self/fd/'+str(fds['native']),p['native_sha256'])
    deployment=Deployment.verify(p['deployment'],key,time.time)
    return run_owner_nonresearch_launcher(deployment=deployment,worker_pidfd=203,native=native,signer_fd=fds['signer'],delegation=p['delegation'],owner_public_key=key,job_kill_fd=fds['job_kill'],subject_kill_fd=fds['subject_kill'],credential_scope=broker,evidence_scope=broker,authorization=broker,binding=p['binding'],resources=Resources(**p['resources']),deadline=time.monotonic()+p['deadline_seconds'])


def main(role):
    if role not in {'OWNER','LAUNCHER'}:raise Denied('compiled role')
    # Read-only image public key; never accept a key from the bootstrap packet.
    fd=os.open('/owner-public-key',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if not os.fstatvfs(fd).f_flag&os.ST_RDONLY or os.fstat(fd).st_size!=32:raise Denied('bootstrap root not readonly image')
        key=os.read(fd,33)
    finally:os.close(fd)
    channel=socket.socket(fileno=200 if role=='LAUNCHER' else 201)
    p,fds=receive_bootstrap(channel,key,role)
    try:
        if role=='LAUNCHER':return assemble_launcher(p,fds,key)
        service=assemble_owner(p,fds,key)
        try:
            service.start();return service.serve(deadline=time.monotonic()+p['deadline_seconds'],cancel_fd=fds['cancel'])
        finally:service.cancel()
    finally:
        for fd in fds.values():os.close(fd)
        channel.close()


class OwnerBrokerServer:
    """Retained private channel, concrete dispatch to existing owner capabilities.

    The owner creates this outside Job scope and binds it to its retained
    ProcessRecord before transferring the other socket through bootstrap.
    Neither public RPC nor Workflow can mint/replace this association.
    """
    def __init__(self,channel,*,role,record,credential_scope,evidence_scope,token_provider=None,canary_authorization=None,binding=None):
        if role not in {'OWNER','LAUNCHER'}:raise Denied('broker closed role')
        if not callable(getattr(record,'verify',None)):raise Denied('broker retained process required')
        for method in ('revoke','revoke_all'):
            if not callable(getattr(credential_scope,method,None)):raise Denied('broker credential scope missing')
        for method in ('preserve_partial','preserve_authenticated_original','seal_complete'):
            if not callable(getattr(evidence_scope,method,None)):raise Denied('broker evidence scope missing')
        if role=='LAUNCHER':
            from .nonresearch_images import closed_binding
            closed_binding(binding)
        elif binding is not None:raise Denied('owner broker binding expansion')
        self.binding=binding
        self.channel=channel;self.role=role;self.record=record
        self.credentials=credential_scope;self.evidence=evidence_scope
        self.token_provider=token_provider;self.authorization=canary_authorization
        self.sealed=False;self.revoked=False;self.original=False
        channel.settimeout(30)

    def serve_once(self):
        self.record.verify()
        def read(n):
            out=[]
            while n:
                part=self.channel.recv(n)
                if not part:raise Denied('broker EOF')
                out.append(part);n-=len(part)
            return b''.join(out)
        size=struct.unpack('!I',read(4))[0]
        if not 0<size<=34*1024*1024:raise Denied('broker request bound')
        request=decode(read(size))
        if type(request) is not dict or set(request)!={'operation','argument'}:raise Denied('broker request schema')
        operation,argument=request['operation'],request['argument']
        allowed={'credential.revoke_all','credential.token','evidence.partial'} if self.role=='OWNER' else {'credential.revoke','credential.canary_live','evidence.partial','evidence.original','evidence.seal'}
        if operation not in allowed:raise Denied('broker operation/role mismatch')
        self.record.verify()
        if operation in {'credential.revoke','credential.revoke_all'}:
            if argument is not None:raise Denied('broker revoke arguments')
            result=getattr(self.credentials,'revoke' if self.role=='LAUNCHER' else 'revoke_all')();self.revoked=True
        elif operation=='credential.token':
            if argument is not None or self.revoked or not callable(self.token_provider):raise Denied('broker token unavailable')
            result=self.token_provider()
            if type(result) is not str or not result:raise Denied('broker token unavailable')
        elif operation=='credential.canary_live':
            if argument!={'role':'LIFE','subject':SUBJECT}:raise Denied('broker only nonresearch canary')
            result=not self.revoked and self.authorization is not None and self.authorization.check_live('LIFE',SUBJECT) is True
        elif operation=='evidence.partial':
            if type(argument) is not str or not 1<=len(argument)<=128 or not argument.isascii():raise Denied('broker partial reason')
            result=self.evidence.preserve_partial(argument)
        elif operation=='evidence.original':
            if self.revoked or self.sealed or self.original or type(argument) is not dict or set(argument)!={'artifact_hex','completion'}:raise Denied('broker original one shot')
            try:raw=bytes.fromhex(argument['artifact_hex'])
            except (TypeError,ValueError) as exc:raise Denied('broker original encoding') from exc
            if not 0<len(raw)<=16*1024*1024:raise Denied('broker original bound')
            completion=argument['completion']
            if type(completion) is not dict or completion.get('status')!='COMPLETE' or canonical(completion.get('binding'))!=canonical(self.binding):raise Denied('broker completion binding')
            artifacts=completion.get('artifacts')
            import hashlib
            if type(artifacts) is not list or len(artifacts)!=1 or artifacts[0].get('sha256')!=hashlib.sha256(raw).hexdigest() or artifacts[0].get('size_bytes')!=len(raw):raise Denied('broker original digest')
            result=self.evidence.preserve_authenticated_original(raw,completion);self.original=True
        else:
            if argument is not None or self.revoked or self.sealed or not self.original:raise Denied('broker complete requires original')
            result=self.evidence.seal_complete();self.sealed=True
        # Concrete backends may return opaque objects; no object serialization
        # or evaluator truth crosses this channel. Only JSON receipts do.
        response=canonical({'ok':True,'result':result})
        if len(response)>65536:raise Denied('broker response bound')
        self.channel.sendall(struct.pack('!I',len(response))+response)
        return operation
