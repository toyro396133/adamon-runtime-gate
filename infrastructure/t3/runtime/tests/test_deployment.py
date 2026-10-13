import copy
import os
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from infrastructure.t3.runtime.deployment import Deployment,validate,DOMAIN,IMAGES,ROLES,SOCKETS,BirthOrder,verify_namespace_boundary
from infrastructure.t3.runtime.guest import canonical
from infrastructure.t3.runtime.microvm import Blocked


def payload():
    return {'version':1,'images':{n:'a'*64 for n in IMAGES},'process_executables':{n:'b'*64 for n in ROLES},'listener_network':{'namespace_inode':123,'policy_sha256':'d'*64},'identities':{n:{'uid':1000+i,'gid':2000+i} for i,n in enumerate(sorted(ROLES))},'subjects':[{'role':'CANARY','subject':'nonresearch'}],'policy':{'network':'isolated_no_interfaces','mount':'private_readonly_source_fixture','cgroup':'v2_job_and_subject','sockets':list(SOCKETS),'evidence':'separate_writable_private','filesystem':'closed_jail','credential_order':'birth_guard_key'},'expires_at':200}


def signed(p):
    key=Ed25519PrivateKey.generate()
    return {'payload':p,'signature_hex':key.sign(DOMAIN+canonical(p)).hex()},key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)


def test_owner_signature_immutable_snapshot_and_subject():
    p=payload();e,key=signed(p);d=Deployment.verify(e,key,lambda:100)
    p['images']['kernel']='b'*64
    assert d.payload()['images']['kernel']=='a'*64
    d.require_subject('CANARY','nonresearch')
    with pytest.raises(Blocked):d.require_subject('LIFE','normal')
    with pytest.raises(Blocked):Deployment.verify(e,key,lambda:100)


@pytest.mark.parametrize('mutation',[lambda p:p.update(command='sh'),lambda p:p['images'].update(kernel='https://example'),lambda p:p['identities']['LAUNCHER'].update(uid=0),lambda p:p['policy'].update(network='host'),lambda p:p['policy']['sockets'].append('/tmp/caller'),lambda p:p.update(version=True)])
def test_reject_authority_expansion(mutation):
    p=payload();mutation(p)
    with pytest.raises(Blocked):validate(p)


def test_real_sealed_descriptors_and_mutable_rejection():
    import fcntl
    data=b'pinned';sha=hashlib.sha256(data).hexdigest();p=payload();p['images']={n:sha for n in IMAGES};e,key=signed(p);d=Deployment.verify(e,key,lambda:100)
    fd=os.memfd_create('test-deployment',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.write(fd,data)
        with pytest.raises(Blocked):d.verify_images({n:fd for n in IMAGES})
        fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
        assert len(d.verify_images({n:fd for n in IMAGES}))==9
        with pytest.raises(PermissionError):os.write(fd,b'mutate')
    finally:os.close(fd)


def test_credential_birth_guard_order_is_one_shot():
    class Process:
        def verify(self):pass
    b=BirthOrder()
    with pytest.raises(Blocked):b.credential(lambda p:None)
    b.born(Process())
    with pytest.raises(Blocked):b.credential(lambda p:None)
    b.guarded(lambda p:None);assert b.credential(lambda p:'key')=='key'
    with pytest.raises(Blocked):b.credential(lambda p:None)


def test_current_process_never_claims_isolated_namespace():
    ns={n:os.stat('/proc/self/ns/'+n).st_ino for n in ('net','mnt','pid','ipc','uts')}
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        with pytest.raises(Blocked):verify_namespace_boundary(os.getpid(),os.getuid(),os.getgid(),'/not-job',ns,fd,fd,fd)
    finally:os.close(fd)


def test_native_provisioning_rejects_supervisor_namespace_before_mount(tmp_path):
    import subprocess,ctypes
    from pathlib import Path
    source=Path(__file__).resolve().parents[2]/'security'/'native_supervisor.c'
    target=tmp_path/'native.so'
    subprocess.run(['gcc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-o',str(target)],check=True)
    lib=ctypes.CDLL(str(target),use_errno=True)
    fn=lib.p4_provision_jail;fn.argtypes=[ctypes.c_int]*4+[ctypes.c_ulong]*2
    fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    before=list(tmp_path.iterdir())
    try:
        assert fn(fd,fd,fd,fd,os.stat('/proc/self/ns/mnt').st_ino,os.stat('/proc/self/ns/net').st_ino)==-1
        assert ctypes.get_errno()==1
        assert list(tmp_path.iterdir())==before
    finally:os.close(fd)


def test_launcher_failed_start_reaps_real_child_without_kvm():
    import subprocess,sys
    from infrastructure.t3.runtime.launcher import LocalLauncher
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    launcher=LocalLauncher(None,None,None,None)
    launcher.process=child;launcher.pidfd=os.pidfd_open(child.pid)
    class Clock:
        def __init__(self):self.tick=0
        def __call__(self):self.tick+=1;return self.tick
    with pytest.raises(Blocked,match='STARTUP_TIMEOUT'):
        launcher.await_api(timeout=.01,clock=Clock())
    assert child.poll() is not None
    assert launcher.process is None


def test_injection_concurrent_replay_only_one_verified():
    from concurrent.futures import ThreadPoolExecutor
    from infrastructure.t3.runtime.injection import InjectionVerifier,issue
    from infrastructure.t3.runtime.tests.test_guest import binding
    owner=Ed25519PrivateKey.generate();key=owner.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    b=binding();source=b'source';fixture=b'fixture'
    b['source_sha256']=hashlib.sha256(source).hexdigest();b['fixture_sha256']=hashlib.sha256(fixture).hexdigest()
    completion=b'k'*32
    e=issue(b,source,fixture,completion,101,owner)
    v=InjectionVerifier(key,b,completion,clock=lambda:100)
    def consume():
        try:v.consume(e,source,fixture);return 'accepted'
        except Blocked:return 'rejected'
    with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(lambda _:consume(),range(20)))
    assert results.count('accepted')==1


def test_watchdog_stop_cannot_leave_real_child_alive(tmp_path):
    import subprocess,sys,time
    from infrastructure.t3.runtime.watchdog import monitor
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    pidfd=os.pidfd_open(child.pid);supervisorfd=os.pidfd_open(os.getpid())
    reader,writer=os.pipe();os.write(writer,b'S')
    kill=os.open(tmp_path/'kill',os.O_RDWR|os.O_CREAT,0o600)
    marker=os.open(tmp_path/'partial',os.O_RDWR|os.O_CREAT,0o600)
    try:
        assert monitor(supervisorfd,[pidfd],kill,reader,marker,time.monotonic()+1)=='WATCHDOG_PREMATURE_STOP'
        assert child.wait(timeout=5)!=0
        assert (tmp_path/'partial').read_text()=='WATCHDOG_PREMATURE_STOP\n'
    finally:
        for fd in (pidfd,supervisorfd,reader,writer,kill,marker):os.close(fd)
        if child.poll() is None:child.kill();child.wait()


def test_process_ownership_separates_watchdog_from_cancellation_scope():
    from infrastructure.t3.runtime.deployment import ProcessOwnership
    from types import SimpleNamespace
    p=payload();e,key=signed(p);d=Deployment.verify(e,key,lambda:100)
    records={role:SimpleNamespace(uid=p['identities'][role]['uid'],executable_sha256=p['process_executables'][role],pidfd=i+10,cgroup='0::/job/subject' if role in {'WORKER','LAUNCHER'} else '0::/owner',verify=lambda:None) for i,role in enumerate(sorted(ROLES))}
    assert ProcessOwnership(d,records,'/job').verify()
    records['WATCHDOG'].cgroup='0::/job/watchdog'
    with pytest.raises(Blocked,match='CONTROL_INSIDE_JOB'):ProcessOwnership(d,records,'/job')


def test_deployment_expiry_rechecked_before_dispatch():
    now=[100];e,key=signed(payload());d=Deployment.verify(e,key,lambda:now[0])
    d.require_subject('CANARY','nonresearch');now[0]=200
    with pytest.raises(Blocked,match='EXPIRED'):d.require_subject('CANARY','nonresearch')


def test_listener_network_never_accepts_host_namespace():
    from infrastructure.t3.runtime.deployment import ListenerNetwork
    fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
    try:
        p=payload();p['listener_network']['namespace_inode']=os.fstat(fd).st_ino;e,key=signed(p)
        with pytest.raises(Blocked,match='NETWORK_PIN'):ListenerNetwork(fd).verify(Deployment.verify(e,key,lambda:100))
    finally:os.close(fd)


def test_signed_volume_version_and_original_bytes_bound(tmp_path):
    from infrastructure.t3.runtime.deployment import EvidenceVolume
    import fcntl
    fd=os.memfd_create('audit-original-volume',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    owner=Ed25519PrivateKey.generate();key=owner.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    try:
        os.write(fd,b'ORIGINAL');st=os.fstat(fd)
        p={'version':1,'role':'AUDIT','subject':'immutable_audit','device':st.st_dev,'inode':st.st_ino,'encrypted_storage_receipt_sha256':'e'*64,'version_id':'immutable-v1','sha256':hashlib.sha256(b'ORIGINAL').hexdigest(),'expires_at':200}
        e={'payload':p,'signature_hex':owner.sign(b'ADAMON-T3-EVIDENCE-VOLUME-V1\0'+canonical(p)).hex()}
        with pytest.raises(Blocked,match='MUTABLE'):EvidenceVolume.verify(fd,e,key,lambda:100)
        fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
        assert EvidenceVolume.verify(fd,e,key,lambda:100).read_only is True
        p['version_id']='replacement-v2'
        with pytest.raises(Blocked,match='SIGNATURE'):EvidenceVolume.verify(fd,e,key,lambda:100)
    finally:os.close(fd)
