"""Actual process/AF_UNIX/Ed25519 integration; NOT Firecracker/KVM proof."""
import hashlib
import multiprocessing
import socket
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.runtime.guest import GuestClient, serve_guest
from infrastructure.t3.runtime.injection import issue, InjectionVerifier, AuthenticatedGuestImage
from infrastructure.t3.runtime.vsock import connect_guest
from infrastructure.t3.runtime.microvm import Blocked


def binding():
    return dict(job_id=1,run_id=2,run_attempt=1,workflow_sha='a'*40,
        assignment_sha256='b'*64,launcher_spki_sha256='c'*64,permit_sha256='d'*64,
        role='LIFE',subject='NONRESEARCH_SOCKET_CANARY',
        source_sha256=hashlib.sha256(b'nonresearch source').hexdigest(),
        fixture_sha256=hashlib.sha256(b'nonresearch fixture').hexdigest())


def guest_process(fd, b, owner_key, completion_key):
    stream=socket.socket(fileno=fd)
    assert stream.recv(11)==b'CONNECT 52\n'
    stream.sendall(b'OK 12345\n')
    def canary(verified_source, verified_fixture):
        payload=verified_source+b':'+verified_fixture
        return [dict(object_id='e'*64,version_id='canary-v1',
             sha256=hashlib.sha256(payload).hexdigest(),size_bytes=len(payload))]
    AuthenticatedGuestImage(b,owner_key,Ed25519PrivateKey.from_private_bytes(completion_key),
        b'nonresearch source',b'nonresearch fixture',
        {('LIFE','NONRESEARCH_SOCKET_CANARY'):canary}).serve(stream)
    stream.close()


def test_real_child_guest_signed_injection_completion():
    owner=Ed25519PrivateKey.generate(); key=Ed25519PrivateKey.generate(); b=binding()
    a,z=socket.socketpair()
    ctx=multiprocessing.get_context('fork')
    child=ctx.Process(target=guest_process,args=(z.fileno(),b,
         owner.public_key().public_bytes_raw(),key.private_bytes_raw()))
    child.start(); z.close()
    try:
        stream=connect_guest(a)
        client=GuestClient(stream,b,key.public_key().public_bytes_raw())
        envelope=issue(b,b'nonresearch source',b'nonresearch fixture',
                       key.public_key().public_bytes_raw(),int(time.time())+60,owner)
        client.execute(envelope)
        result=None
        for _ in range(20):
            result=client.poll_completion(.1)
            if result is not None: break
        assert result['status']=='COMPLETE'
        assert result['binding']==b
        child.join(2); assert child.exitcode==0
    finally:
        a.close()
        if child.is_alive(): child.kill(); child.join()


def test_injection_replay_wrong_source_and_expiry_fail_closed():
    owner=Ed25519PrivateKey.generate(); key=Ed25519PrivateKey.generate(); b=binding()
    e=issue(b,b'nonresearch source',b'nonresearch fixture',key.public_key().public_bytes_raw(),100,owner)
    v=InjectionVerifier(owner.public_key().public_bytes_raw(),b,key.public_key().public_bytes_raw(),clock=lambda:50)
    with pytest.raises(Blocked,match='SOURCE_PIN'):
        v.consume(e,b'nonresearch sourcE',b'nonresearch fixture')
    assert v.consume(e,b'nonresearch source',b'nonresearch fixture')
    with pytest.raises(Blocked,match='REPLAY'): v.consume(e,b'nonresearch source',b'nonresearch fixture')
    with pytest.raises(Blocked,match='EXPIRED'):
        InjectionVerifier(owner.public_key().public_bytes_raw(),b,key.public_key().public_bytes_raw(),clock=lambda:100).consume(e,b'nonresearch source',b'nonresearch fixture')


def test_wrong_job_signed_injection_rejected():
    owner=Ed25519PrivateKey.generate(); key=Ed25519PrivateKey.generate(); b=binding()
    e=issue(b,b'nonresearch source',b'nonresearch fixture',key.public_key().public_bytes_raw(),100,owner)
    other=dict(b,run_attempt=2)
    with pytest.raises(Blocked,match='BINDING'):
        InjectionVerifier(owner.public_key().public_bytes_raw(),other,key.public_key().public_bytes_raw(),clock=lambda:50).consume(e,b'nonresearch source',b'nonresearch fixture')


def test_watchdog_actual_pidfd_cancellation_preserves_marker(tmp_path):
    import os
    import threading
    from infrastructure.t3.runtime.watchdog import monitor
    child=multiprocessing.get_context('fork').Process(target=time.sleep,args=(60,))
    child.start()
    child_fd=os.pidfd_open(child.pid); supervisor=os.pidfd_open(os.getpid())
    reader,writer=os.pipe()
    # Regular file deliberately stands in for cgroup control for this bounded
    # test; kernel pidfd_send_signal below is real. This proves no cgroup claim.
    kill_fd=os.open(tmp_path/'synthetic-cgroup-control',os.O_CREAT|os.O_RDWR,0o600)
    marker=os.open(tmp_path/'partial',os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600)
    try:
        os.write(writer,b'R')
        assert monitor(supervisor,[child_fd],kill_fd,reader,marker,time.monotonic()+2)=='WATCHDOG_REVOKED'
        child.join(2); assert child.exitcode==-9
        assert (tmp_path/'partial').read_text()=='WATCHDOG_REVOKED\n'
    finally:
        for fd in (child_fd,supervisor,reader,writer,kill_fd,marker): os.close(fd)
        if child.is_alive(): child.kill(); child.join()


def test_launcher_sealed_bytes_and_mutable_source_denial(tmp_path):
    import os
    import fcntl
    from infrastructure.t3.runtime.launcher import ImmutableFD
    content=b'nonresearch executable pin only'
    digest=hashlib.sha256(content).hexdigest()
    path=tmp_path/'mutable'
    path.write_bytes(content)
    fd=os.open(path,os.O_RDONLY)
    try:
        with pytest.raises(Blocked,match='MUTABLE_SOURCE'): ImmutableFD(fd,digest).verify()
    finally: os.close(fd)
    sealed=os.memfd_create('nonresearch-vmm-pin',os.MFD_ALLOW_SEALING)
    try:
        os.write(sealed,content)
        fcntl.fcntl(sealed,1033,8|4|2|1)
        ImmutableFD(sealed,digest).verify()
        with pytest.raises(Blocked,match='DIGEST'): ImmutableFD(sealed,'0'*64).verify()
    finally: os.close(sealed)


def test_signed_injection_completion_key_substitution_denied():
    owner=Ed25519PrivateKey.generate(); key=Ed25519PrivateKey.generate(); b=binding()
    e=issue(b,b'nonresearch source',b'nonresearch fixture',key.public_key().public_bytes_raw(),100,owner)
    other=Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(Blocked,match='COMPLETION_KEY_BINDING'):
        InjectionVerifier(owner.public_key().public_bytes_raw(),b,other,clock=lambda:50).consume(e,b'nonresearch source',b'nonresearch fixture')
