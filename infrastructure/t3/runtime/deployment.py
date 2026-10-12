"""Owner-signed closed deployment contracts; never a workflow configuration.

This verifier does not grant research execution or claim privileged provisioning.
Descriptors pin immutable bytes, while namespace checks interrogate the kernel.
"""
from dataclasses import dataclass
import hashlib
import os
import re
import stat
import threading
from types import MappingProxyType
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .guest import canonical
from .launcher import ImmutableFD
from .microvm import Blocked

DOMAIN=b'ADAMON-T3-OWNER-DEPLOYMENT-V1\0'
IMAGES=frozenset({'runner','supervisor','launcher','guest','firecracker','kernel','rootfs','source','fixture'})
ROLES=frozenset({'LISTENER','WORKER','LAUNCHER','WATCHDOG','STORAGE'})
SOCKETS=('/firecracker.socket','/private-control.vsock','/launcher-bootstrap.socket')
SHA=re.compile('[0-9a-f]{64}')


def validate(payload):
    if type(payload) is not dict or set(payload)!={'version','images','process_executables','listener_network','identities','subjects','policy','expires_at'}:
        raise Blocked('DEPLOYMENT_SHAPE')
    if type(payload['version']) is not int or payload['version']!=1:
        raise Blocked('DEPLOYMENT_VERSION')
    images=payload['images']
    if type(images) is not dict or set(images)!=IMAGES or any(type(v) is not str or not SHA.fullmatch(v) for v in images.values()):
        raise Blocked('DEPLOYMENT_IMAGE_PINS')
    executables=payload['process_executables']
    if type(executables) is not dict or set(executables)!=ROLES or any(type(v) is not str or not SHA.fullmatch(v) for v in executables.values()):
        raise Blocked('DEPLOYMENT_PROCESS_EXECUTABLE_PINS')
    network=payload['listener_network']
    if type(network) is not dict or set(network)!={'namespace_inode','policy_sha256'} or type(network['namespace_inode']) is not int or network['namespace_inode']<=0 or type(network['policy_sha256']) is not str or not SHA.fullmatch(network['policy_sha256']):
        raise Blocked('DEPLOYMENT_LISTENER_NETWORK')
    ids=payload['identities']
    if type(ids) is not dict or set(ids)!=ROLES:raise Blocked('DEPLOYMENT_IDENTITIES')
    for v in ids.values():
        if type(v) is not dict or set(v)!={'uid','gid'} or any(type(n) is not int or not 1<=n<2**31 for n in v.values()):
            raise Blocked('DEPLOYMENT_UID_GID')
    if len({v['uid'] for v in ids.values()})!=len(ROLES) or len({v['gid'] for v in ids.values()})!=len(ROLES):
        raise Blocked('DEPLOYMENT_IDENTITY_SEPARATION')
    subjects=payload['subjects']
    if type(subjects) is not list or not subjects:raise Blocked('DEPLOYMENT_SUBJECTS')
    tuples=[]
    for s in subjects:
        if type(s) is not dict or set(s)!={'role','subject'} or s['role'] not in {'LIFE','MICRO','AUDIT','AGGREGATION','CANARY'} or type(s['subject']) is not str or not re.fullmatch('[a-zA-Z0-9_+-]{1,128}',s['subject']):
            raise Blocked('DEPLOYMENT_SUBJECT')
        tuples.append((s['role'],s['subject']))
    if len(set(tuples))!=len(tuples):raise Blocked('DEPLOYMENT_DUPLICATE_SUBJECT')
    expected={'network':'isolated_no_interfaces','mount':'private_readonly_source_fixture','cgroup':'v2_job_and_subject','sockets':list(SOCKETS),'evidence':'separate_writable_private','filesystem':'closed_jail','credential_order':'birth_guard_key'}
    if canonical(payload['policy'])!=canonical(expected):raise Blocked('DEPLOYMENT_POLICY')
    if type(payload['expires_at']) is not int or payload['expires_at']<=0:raise Blocked('DEPLOYMENT_EXPIRY')


@dataclass(frozen=True)
class Deployment:
    """Verified immutable authority. Construction uses verify() only in broker."""
    canonical_payload: bytes
    sha256: str
    clock: object

    @classmethod
    def verify(cls,envelope,owner_public_key,clock):
        if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:raise Blocked('DEPLOYMENT_ENVELOPE')
        payload=envelope['payload'];validate(payload)
        if not clock()<payload['expires_at']:raise Blocked('DEPLOYMENT_EXPIRED')
        sig=envelope['signature_hex']
        if type(sig) is not str or not re.fullmatch('[0-9a-f]{128}',sig):raise Blocked('DEPLOYMENT_SIGNATURE')
        raw=canonical(payload)
        try:Ed25519PublicKey.from_public_bytes(owner_public_key).verify(bytes.fromhex(sig),DOMAIN+raw)
        except Exception as exc:raise Blocked('DEPLOYMENT_SIGNATURE') from exc
        return cls(raw,hashlib.sha256(raw).hexdigest(),clock)

    def payload(self):
        import json
        value=json.loads(self.canonical_payload)
        if not self.clock()<value['expires_at']:raise Blocked('DEPLOYMENT_EXPIRED')
        return value

    def verify_images(self,descriptors):
        if set(descriptors)!=IMAGES:raise Blocked('DEPLOYMENT_DESCRIPTOR_SET')
        payload=self.payload()
        for name,fd in descriptors.items():ImmutableFD(fd,payload['images'][name]).verify()
        return MappingProxyType(dict(descriptors))

    def require_subject(self,role,subject):
        if {'role':role,'subject':subject} not in self.payload()['subjects']:
            raise Blocked('DEPLOYMENT_UNAUTHORIZED_SUBJECT')


def verify_namespace_boundary(pid,expected_uid,expected_gid,expected_cgroup,parent_namespace_ids,source_fd,fixture_fd,evidence_fd):
    """Kernel observed checks, not trust in six caller-provided booleans.

    Caller holds ProcessRecord.pidfd and verifies it immediately before/after
    invocation. This function is a verifier, not authorization or namespace birth.
    """
    if type(pid) is not int or pid<=0:raise Blocked('DEPLOYMENT_PID')
    with open(f'/proc/{pid}/status') as f:status=f.read()
    fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
    if [int(x) for x in fields['Uid'].split()]!=[expected_uid]*4 or [int(x) for x in fields['Gid'].split()]!=[expected_gid]*4:
        raise Blocked('DEPLOYMENT_PROCESS_UID_GID')
    if fields.get('NoNewPrivs')!='1' or fields.get('Seccomp')!='2':raise Blocked('DEPLOYMENT_PROCESS_GUARD')
    if int(fields.get('CapEff','1'),16)!=0:raise Blocked('DEPLOYMENT_CAPABILITIES')
    for ns in ('net','mnt','pid','ipc','uts'):
        inode=os.stat(f'/proc/{pid}/ns/{ns}').st_ino
        if ns not in parent_namespace_ids or inode==parent_namespace_ids[ns]:raise Blocked('DEPLOYMENT_NAMESPACE_'+ns)
    with open(f'/proc/{pid}/cgroup') as f:cgroups=f.read().splitlines()
    if cgroups!=['0::'+expected_cgroup]:raise Blocked('DEPLOYMENT_CGROUP')
    with open(f'/proc/{pid}/net/dev') as f:interfaces=[x.split(':')[0].strip() for x in f.read().splitlines()[2:] if ':' in x]
    if set(interfaces)-{'lo'}:raise Blocked('DEPLOYMENT_NETWORK_INTERFACES')
    with open(f'/proc/{pid}/net/route') as f:routes=f.read().splitlines()[1:]
    if routes:raise Blocked('DEPLOYMENT_NETWORK_ROUTES')
    for fd in (source_fd,fixture_fd):
        if not os.fstatvfs(fd).f_flag&os.ST_RDONLY:raise Blocked('DEPLOYMENT_READONLY_MOUNTS')
    if os.fstatvfs(evidence_fd).f_flag&os.ST_RDONLY:raise Blocked('DEPLOYMENT_WRITABLE_EVIDENCE')
    if os.fstat(evidence_fd).st_dev in {os.fstat(source_fd).st_dev,os.fstat(fixture_fd).st_dev}:
        raise Blocked('DEPLOYMENT_EVIDENCE_FILESYSTEM_SEPARATION')
    return {'status':'KERNEL_BOUNDARY_OBSERVED','pid':pid}


class BirthOrder:
    """One-shot birth ordering: credentials cannot precede immutable guard.

    Controller owns this object; neither guest nor Workflow receives it. Actual
    guard implementation must be native and irreversible; injected operations
    here are verified through subsequent ProcessRecord/kernel checks.
    """
    def __init__(self):
        self.state='NEW'
        self._lock=threading.RLock()
    def born(self,process_record):
        with self._lock:return self._born_locked(process_record)
    def _born_locked(self,process_record):
        if self.state!='NEW':raise Blocked('DEPLOYMENT_BIRTH_ORDER')
        process_record.verify();self.record=process_record;self.state='BORN'
    def guarded(self,verify_kernel_guard):
        with self._lock:return self._guarded_locked(verify_kernel_guard)
    def _guarded_locked(self,verify_kernel_guard):
        if self.state!='BORN':raise Blocked('DEPLOYMENT_GUARD_ORDER')
        self.record.verify();verify_kernel_guard(self.record);self.record.verify();self.state='GUARDED'
    def credential(self,issue):
        with self._lock:return self._credential_locked(issue)
    def _credential_locked(self,issue):
        if self.state!='GUARDED':raise Blocked('DEPLOYMENT_CREDENTIAL_ORDER')
        self.record.verify();self.state='CONSUMED'
        return issue(self.record)


@dataclass(frozen=True)
class JailDescriptors:
    """Owner-provisioned directory FDs wired into native child birth only."""
    jail_fd:int
    source_fd:int
    fixture_fd:int
    evidence_fd:int
    parent_mount_inode:int
    parent_net_inode:int

    def __post_init__(self):
        for fd in (self.jail_fd,self.source_fd,self.fixture_fd,self.evidence_fd):
            if type(fd) is not int or fd<0 or not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise Blocked('DEPLOYMENT_JAIL_DIRECTORY_FD')
            os.set_inheritable(fd,False)
        for inode in (self.parent_mount_inode,self.parent_net_inode):
            if type(inode) is not int or inode<=0:raise Blocked('DEPLOYMENT_PARENT_NAMESPACE_PIN')


class ProcessOwnership:
    """Five closed host capabilities; no PID/path accepted from the Workflow.

    Watchdog must survive full Job cgroup teardown, while all subject and
    Worker processes are subordinate to it. A storage broker may run in the
    owner scope so that final partial evidence survives cancellation.
    """
    def __init__(self,deployment,records,job_cgroup):
        if set(records)!=ROLES or type(job_cgroup) is not str or not job_cgroup.startswith('/') or '..' in job_cgroup.split('/'):
            raise Blocked('DEPLOYMENT_OWNERSHIP_SHAPE')
        self.deployment=deployment;self.records=MappingProxyType(dict(records));self.job_cgroup=job_cgroup
        self.verify()

    def verify(self):
        authority=self.deployment.payload()
        for role,record in self.records.items():
            record.verify()
            if record.uid!=authority['identities'][role]['uid'] or record.executable_sha256!=authority['process_executables'][role]:
                raise Blocked('DEPLOYMENT_OWNERSHIP_IDENTITY')
            if not record.cgroup.startswith('0::/') or '\n' in record.cgroup:raise Blocked('DEPLOYMENT_CGROUP_V2')
            cgroup_path=record.cgroup[3:]
            inside=cgroup_path==self.job_cgroup or cgroup_path.startswith(self.job_cgroup.rstrip('/')+'/')
            if role in {'WORKER','LAUNCHER'} and not inside:
                raise Blocked('DEPLOYMENT_PROCESS_OUTSIDE_JOB')
            if role in {'WATCHDOG','STORAGE'} and inside:
                raise Blocked('DEPLOYMENT_CONTROL_INSIDE_JOB')
        if len({r.pidfd for r in self.records.values()})!=len(ROLES):
            raise Blocked('DEPLOYMENT_PROCESS_ALIAS')
        return True


@dataclass(frozen=True)
class VMAssetDescriptors:
    """Signed deployment image FDs plus trusted /dev/kvm owner-opened FD."""
    firecracker_fd:int
    kernel_fd:int
    rootfs_fd:int
    kvm_fd:int

    def verify(self,deployment):
        p=deployment.payload()['images']
        for name,fd in (('firecracker',self.firecracker_fd),('kernel',self.kernel_fd),('rootfs',self.rootfs_fd)):
            ImmutableFD(fd,p[name]).verify()
        mode=os.fstat(self.kvm_fd)
        if not stat.S_ISCHR(mode.st_mode) or (os.major(mode.st_rdev),os.minor(mode.st_rdev))!=(10,232):
            raise Blocked('DEPLOYMENT_KVM_DESCRIPTOR')
        return self


@dataclass(frozen=True)
class ListenerNetwork:
    """Owner-provisioned restricted namespace, never host network fallback.

    Signature pins namespace inode plus egress-policy evidence digest. Runtime
    firewall/egress verification remains privileged preflight, not this helper.
    """
    fd:int

    def verify(self,deployment):
        import fcntl
        expected=deployment.payload()['listener_network']
        actual=os.fstat(self.fd)
        if actual.st_ino!=expected['namespace_inode'] or actual.st_ino==os.stat('/proc/self/ns/net').st_ino:
            raise Blocked('DEPLOYMENT_LISTENER_NETWORK_PIN')
        if fcntl.ioctl(self.fd,0xb703)!=0x40000000: # NS_GET_NSTYPE, CLONE_NEWNET
            raise Blocked('DEPLOYMENT_LISTENER_NAMESPACE_TYPE')
        return self


@dataclass(frozen=True)
class EvidenceVolume:
    """Storage-owner attested encrypted volume. No formatting or key creation.

    Host encryption/VersionId provenance is independently signed by storage
    owner and must be verified live by preflight. This binding cannot itself
    prove encrypted filesystem internals.
    """
    fd:int
    read_only:bool
    authority_bytes:bytes

    @classmethod
    def verify(cls,fd,envelope,owner_public_key,clock):
        if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:raise Blocked('VOLUME_ENVELOPE')
        p=envelope['payload']
        if type(p) is not dict or set(p)!={'version','role','subject','device','inode','encrypted_storage_receipt_sha256','version_id','sha256','expires_at'} or type(p['version']) is not int or p['version']!=1:
            raise Blocked('VOLUME_SCHEMA')
        for k in ('device','inode','expires_at'):
            if type(p[k]) is not int or p[k]<=0:raise Blocked('VOLUME_IDENTITY')
        if type(p['encrypted_storage_receipt_sha256']) is not str or not SHA.fullmatch(p['encrypted_storage_receipt_sha256']):raise Blocked('VOLUME_CRYPTO_PROVENANCE')
        if p['role'] not in {'LIFE','MICRO','AUDIT','AGGREGATION','CANARY'} or type(p['subject']) is not str or not p['subject']:raise Blocked('VOLUME_SUBJECT')
        if not clock()<p['expires_at']:raise Blocked('VOLUME_EXPIRED')
        raw=canonical(p)
        try:Ed25519PublicKey.from_public_bytes(owner_public_key).verify(bytes.fromhex(envelope['signature_hex']),b'ADAMON-T3-EVIDENCE-VOLUME-V1\0'+raw)
        except Exception as exc:raise Blocked('VOLUME_SIGNATURE') from exc
        st=os.fstat(fd)
        if (st.st_dev,st.st_ino)!=(p['device'],p['inode']) or not stat.S_ISREG(st.st_mode):raise Blocked('VOLUME_DESCRIPTOR_PIN')
        if p['role']=='AUDIT':
            if type(p['version_id']) is not str or not p['version_id'] or type(p['sha256']) is not str or not SHA.fullmatch(p['sha256']):raise Blocked('VOLUME_AUDIT_VERSION')
            ImmutableFD(fd,p['sha256']).verify()
        elif p['version_id'] is not None or p['sha256'] is not None:raise Blocked('VOLUME_WRITABLE_IDENTITY')
        return cls(fd,p['role']=='AUDIT',raw)
