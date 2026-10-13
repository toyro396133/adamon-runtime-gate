"""Actual child/pidfd and AF_UNIX guest transports; no KVM/namespace proof."""
import hashlib
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.security.native import NativeProcessFactory
from infrastructure.t3.security.process import ProcessRecord
from infrastructure.t3.security.protocol import Denied
from infrastructure.t3.runtime.launcher import LocalLauncher
from infrastructure.t3.runtime.guest import BINDING
from infrastructure.t3.runtime.microvm import Blocked
from infrastructure.t3.deployment.nonresearch_images import (NonresearchBootGuest,
    serve_nonresearch_image,SUBJECT,SOURCE,FIXTURE)
from infrastructure.t3.deployment.delegation import issue_delegation,verify_delegation
from infrastructure.t3.deployment.build_bundle import source_manifest,build_bundle
from infrastructure.t3.deployment.rootfs_build import assemble_tree,verify_base


def binding():
    value={k:'a'*(40 if k=='workflow_sha' else 64) for k in BINDING}
    value.update(job_id=1,run_id=2,run_attempt=1,role='LIFE',subject=SUBJECT,
                 source_sha256=hashlib.sha256(SOURCE).hexdigest(),fixture_sha256=hashlib.sha256(FIXTURE).hexdigest())
    return value


def child_record(child):
    base=Path('/proc')/str(child.pid);raw=(base/'stat').read_text()
    return ProcessRecord(child.pid,os.pidfd_open(child.pid),os.getuid(),
         int(raw[raw.rfind(')')+2:].split()[19]),(base/'cgroup').read_text().strip(),
         hashlib.sha256((base/'exe').read_bytes()).hexdigest())


class ActualChildFactory(NativeProcessFactory):
    def __init__(self,cgroup_fd):
        roles={role:{'exe_fd':0,'sha256':'a'*64,'cgroup_fd':cgroup_fd,'cgroup':'0::/test',
                     'uid':n+1000,'gid':n+1000} for n,role in enumerate(('LISTENER','WORKER','LAUNCHER'))}
        super().__init__(None,roles,exec_timeout=1)
        self.children=[];self.records=[]
    def _spawn_owned(self,role,bootstrap_fd,**kwargs):
        child=subprocess.Popen(['/bin/sleep','30']);self.children.append(child)
        record=child_record(child);self.records.append(record);return record


def test_actual_pidfd_cancel_and_duplicate_role(tmp_path):
    (tmp_path/'cgroup.kill').write_bytes(b'')
    directory=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    factory=ActualChildFactory(directory);partial=[]
    try:
        original=factory.spawn('LISTENER',0);original.verify()
        with pytest.raises(Denied,match='replay'):factory.spawn('LISTENER',0)
        factory.spawn('WORKER',0)
        factory.revoke_owned(partial.append,'SYNTHETIC_CANCEL')
        assert partial==['SYNTHETIC_CANCEL']
        assert all(child.poll() is not None for child in factory.children)
        assert (tmp_path/'cgroup.kill').read_bytes()==b'1'
        with pytest.raises(Denied,match='revoked'):factory.spawn('LAUNCHER',0)
        factory.revoke_owned(partial.append,'SYNTHETIC_CANCEL')
        assert len(partial)==1
    finally:
        for child in factory.children:
            if child.poll() is None:child.kill();child.wait()
        for record in factory.records:os.close(record.pidfd)
        os.close(directory)


def test_cgroup_failure_still_kills_original_pidfd_and_preserves(tmp_path):
    directory=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    factory=ActualChildFactory(directory);partial=[]
    try:
        factory.spawn('WORKER',0)
        with pytest.raises(ExceptionGroup,match='cleanup incomplete'):
            factory.revoke_owned(partial.append,'CGROUP_MISSING')
        assert factory.children[0].poll() is not None
        assert partial==['CGROUP_MISSING']
    finally:
        for record in factory.records:os.close(record.pidfd)
        os.close(directory)


def test_cancel_racing_actual_birth_does_not_lose_child(tmp_path):
    (tmp_path/'cgroup.kill').write_bytes(b'')
    directory=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    factory=ActualChildFactory(directory);entered=threading.Event();release=threading.Event();partial=[]
    original=factory._spawn_owned
    def birth(*args,**kwargs):
        entered.set();release.wait(2);return original(*args,**kwargs)
    factory._spawn_owned=birth
    born=threading.Thread(target=lambda:factory.spawn('WORKER',0));born.start()
    assert entered.wait(2)
    cancel=threading.Thread(target=lambda:factory.revoke_owned(partial.append,'BIRTH_CANCEL'))
    cancel.start();release.set();born.join(3);cancel.join(3)
    try:
        assert not born.is_alive() and not cancel.is_alive()
        assert partial==['BIRTH_CANCEL'];assert factory.children[0].poll() is not None
    finally:
        for record in factory.records:os.close(record.pidfd)
        os.close(directory)


class SocketLauncher(LocalLauncher):
    def __init__(self,stream):self.stream=stream;self.calls=0
    def guest(self):self.calls+=1;return self.stream


def test_real_socket_guest_init_exports_signed_original_sqlite():
    host,guest=socket.socketpair();owner=Ed25519PrivateKey.generate();errors=[]
    def serve():
        try:assert serve_nonresearch_image(guest,owner.public_key().public_bytes_raw())=='NONRESEARCH_COMPLETE'
        except BaseException as exc:errors.append(exc)
        finally:guest.close()
    thread=threading.Thread(target=serve);thread.start()
    delegate=Ed25519PrivateKey.generate()
    delegation=issue_delegation(binding(),delegate.public_key().public_bytes_raw(),int(time.time())+60,owner)
    launcher=SocketLauncher(host);client=NonresearchBootGuest(launcher,binding(),delegate,delegation,owner.public_key().public_bytes_raw())
    try:
        assert launcher.calls==0
        client.execute(timeout=3);completion=client.poll_completion(3)
        assert completion['binding']==binding() and launcher.calls==1
        assert hashlib.sha256(client.artifact).hexdigest()==completion['artifacts'][0]['sha256']
        db=sqlite3.connect(':memory:');db.deserialize(client.artifact)
        assert db.execute('SELECT value FROM canary').fetchall()==[('nonresearch',)];db.close()
        with pytest.raises(Blocked,match='ONE_SHOT'):client.execute()
        thread.join(3);assert not thread.is_alive() and not errors
    finally:client.close();thread.join(3)


@pytest.mark.parametrize('key,value',[('subject','D10-normal'),('role','AUDIT'),('source_sha256','0'*64)])
def test_nonresearch_image_rejects_all_other_subjects(key,value):
    request=binding();request[key]=value
    with pytest.raises(Blocked,match='SUBJECT_ONLY'):
        NonresearchBootGuest(SocketLauncher(None),request,Ed25519PrivateKey.generate(),{},b"a"*32)


def test_build_bundle_exact_bytes_and_one_pin_mutation():
    manifest=source_manifest();a,receipt=build_bundle(manifest);b,other=build_bundle(manifest)
    assert a==b and receipt==other
    assert hashlib.sha256(a).hexdigest()==receipt['sha256']
    assert not receipt['execution_authorized']
    corrupt=dict(manifest);corrupt[next(iter(corrupt))]='0'*64
    with pytest.raises(Blocked,match='PIN_MISMATCH'):build_bundle(corrupt)


def base_tree(tmp_path):
    base=tmp_path/'base';(base/'usr/bin').mkdir(parents=True)
    (base/'usr/lib/python3.12').mkdir(parents=True)
    (base/'usr/bin/python3').write_bytes(b'PINNED_SYNTHETIC_INTERPRETER_NOT_EXECUTED')
    (base/'usr/bin/python3').chmod(0o555)
    (base/'usr/lib/python3.12/os.py').write_bytes(b'# synthetic stdlib')
    manifest={p.relative_to(base).as_posix():{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':p.stat().st_mode&0o7777} for p in base.rglob('*') if p.is_file()}
    return base,manifest


def test_rootfs_source_assembly_and_pin_rejection(tmp_path):
    base,manifest=base_tree(tmp_path);source=source_manifest();staging=tmp_path/'stage'
    receipt=assemble_tree(base,manifest,source,b'p'*32,staging)
    assert (staging/'sbin/init').read_bytes().startswith(b'#!/usr/bin/python3')
    assert (staging/'owner-public-key').read_bytes()==b'p'*32
    assert receipt['source_manifest_sha256']
    with pytest.raises(Blocked,match='STAGING_EXISTS'):assemble_tree(base,manifest,source,b'p'*32,staging)
    (base/'usr/lib/python3.12/os.py').write_bytes(b'SUBSTITUTED')
    with pytest.raises(Blocked,match='PIN_MISMATCH'):verify_base(base,manifest)


def test_rootfs_symlink_base_denied(tmp_path):
    base,manifest=base_tree(tmp_path);(base/'untrusted').symlink_to('/etc/passwd')
    with pytest.raises(Blocked,match='UNSAFE_MEMBER'):verify_base(base,manifest)

@pytest.mark.parametrize('mutation',['key','purpose','expiry','source','job','permit','owner_root'])
def test_canary_delegation_is_scoped_and_cannot_substitute_root(mutation):
    owner=Ed25519PrivateKey.generate();delegate=Ed25519PrivateKey.generate()
    original=binding();now=1000
    envelope=issue_delegation(original,delegate.public_key().public_bytes_raw(),1060,owner)
    assert verify_delegation(envelope,owner.public_key().public_bytes_raw(),original,lambda:now)[0]==delegate.public_key().public_bytes_raw()
    import copy
    changed=copy.deepcopy(envelope)
    if mutation=='key':
        with pytest.raises(Blocked,match='SIGNER_MISMATCH'):
            NonresearchBootGuest(SocketLauncher(None),original,Ed25519PrivateKey.generate(),envelope,owner.public_key().public_bytes_raw(),lambda:now)
        return
    if mutation=='purpose':changed['payload']['purpose']='RESEARCH'
    elif mutation=='expiry':changed['payload']['expires_at']=999
    elif mutation=='source':changed['payload']['binding']['source_sha256']='0'*64
    elif mutation=='job':changed['payload']['binding']['job_id']=99
    elif mutation=='permit':changed['payload']['binding']['permit_sha256']='0'*64
    elif mutation=='owner_root':changed['payload']['delegate_public_key_hex']=owner.public_key().public_bytes_raw().hex()
    from infrastructure.t3.deployment.delegation import DOMAIN
    from infrastructure.t3.runtime.guest import canonical
    # Even correctly owner-signed wrong scope/binding is refused independently
    # of signature integrity, proving the intended mutation is the cause.
    changed['signature_hex']=owner.sign(DOMAIN+canonical(changed['payload'])).hex()
    with pytest.raises(Blocked):verify_delegation(changed,owner.public_key().public_bytes_raw(),original,lambda:now)


def test_cgroup_scope_closed_names_and_wrong_filesystem(tmp_path):
    from infrastructure.t3.deployment.cgroups import scope_names,require_cgroup2
    assert scope_names(43)==('adamon-job-43','adamon-control-43')
    for bad in (0,-1,True,'43','../../other'):
        with pytest.raises(Blocked,match='JOB_ID'):scope_names(bad)
    fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    try:
        with pytest.raises(Blocked,match='FILESYSTEM_REQUIRED'):require_cgroup2(fd)
    finally:os.close(fd)


def test_owner_service_cancel_before_worker_dispatch_kills_listener(tmp_path):
    # Lifecycle method with actual owned pidfd; privileged signature/image
    # construction is NOT replaced with this test or claimed as live proof.
    from infrastructure.t3.deployment.service import OwnerDeploymentService
    (tmp_path/'cgroup.kill').write_bytes(b'')
    directory=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    factory=ActualChildFactory(directory);factory.spawn('LISTENER',0);partial=[];revoked=[]
    class Credentials:
        def revoke_all(self):revoked.append(True)
    class Evidence:
        def preserve_partial(self,reason):partial.append(reason)
    service=object.__new__(OwnerDeploymentService)
    service.factory=factory;service.credentials=Credentials();service.evidence=Evidence()
    service._lock=threading.RLock();service.state='STARTING';service.supervisor=None
    service.channel=None
    try:
        service.cancel()
        assert factory.children[0].poll() is not None
        assert service.state=='STOPPED' and partial==['OWNER_CANCELLED'] and revoked==[True]
        service.cancel();assert len(partial)==1
    finally:
        for record in factory.records:os.close(record.pidfd)
        os.close(directory)


def test_owner_service_no_generic_factory_or_workflow_configuration():
    from infrastructure.t3.deployment.service import OwnerDeploymentService
    with pytest.raises(Denied,match='native factory'):
        OwnerDeploymentService(native_factory=object(),deployment_envelope={},owner_public_key=b'a'*32,
               image_descriptors={},repository='owner/repo',token_provider=None,approved_identity={},
               credential_scope=None,evidence_scope=None)


def test_concrete_launcher_entry_rejects_research_before_any_birth():
    from infrastructure.t3.deployment.launcher_entry import run_owner_nonresearch_launcher
    request=binding();request['subject']='D10-normal'
    with pytest.raises(Blocked,match='SUBJECT_ONLY'):
        run_owner_nonresearch_launcher(deployment=None,worker_pidfd=0,native=None,
              signer_fd=0,delegation={},owner_public_key=b'a'*32,job_kill_fd=0,subject_kill_fd=0,
              credential_scope=None,evidence_scope=None,authorization=None,binding=request,
              resources=None,deadline=1)
