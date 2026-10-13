"""Joined real local kernel/key/socket chain; REST is explicitly synthetic.

No GitHub allocation, privileged native spawn, mTLS or KVM is claimed here.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.runner.assignment import decode_assignment
from infrastructure.t3.runner.tests.test_assignment import packet
from infrastructure.t3.security.supervisor import Supervisor,RunnerAssignmentBinder
from infrastructure.t3.security.protocol import Denied,sign,verify,canonical
from infrastructure.t3.security.ledger import Ledger
from infrastructure.t3.runtime.vertical import NonresearchVerticalController,owned_record,SUBJECT,SOURCE,FIXTURE,RECEIPT_DOMAIN


@pytest.fixture
def setup(tmp_path):
    raw=json.dumps(packet());sha=hashlib.sha256(raw.encode()).hexdigest()
    decoded=decode_assignment(raw,sha)
    class ExplicitSyntheticREST:
        live=True
        def get_run(self,*_):return dict(decoded)
        def list_jobs(self,*_):return [dict(job_id=901,run_id=123,run_attempt=2,
            check_run_id=345,runner_id=7,status='in_progress' if self.live else 'completed')]
    rest=ExplicitSyntheticREST();worker=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    record=owned_record(worker.pid);listener=owned_record(os.getpid())
    def worker_factory(a,b,raw):os.close(a);os.close(b);return record
    supervisor=Supervisor(listener,worker_factory,RunnerAssignmentBinder(decode_assignment,rest,runner_id=7),rest,
        dict(decoded,runner_id=7),lambda *_:None)
    # Direct retained owner-channel context exercises the exact supervisor state
    # machine. C# private bridge transport has separate actual socket tests.
    def message(role,op,payload,fds=()):
        supervisor._private_context.role=role
        try:return supervisor.handle_private_message(role,dict(request_id=str(uuid.uuid4()),operation=op,payload=payload),fds)
        finally:supervisor._private_context.role=None
    fds=[os.open('/dev/null',os.O_RDONLY),os.open('/dev/null',os.O_RDONLY)]
    try:
        message('LISTENER','listener_snapshot_spawn',dict(raw_assignment=raw,assignment_sha256=sha),fds)
    finally:
        for fd in fds:os.close(fd)
    message('WORKER','worker_ack',dict(raw_assignment=raw,assignment_sha256=sha))
    message('WORKER','authorize_assignment',dict(assignment_sha256=sha,step_id=decoded['step_id']))
    owner=Ed25519PrivateKey.generate();receipt=Ed25519PrivateKey.generate()
    binding=dict(job_id=901,run_id=123,run_attempt=2,workflow_sha='a'*40,
        assignment_sha256=sha,launcher_spki_sha256='c'*64,role='LIFE',subject=SUBJECT,
        source_sha256=hashlib.sha256(SOURCE).hexdigest(),fixture_sha256=hashlib.sha256(FIXTURE).hexdigest(),authority_sha256='d'*64,
        repository_id=decoded['repository_id'],workflow_path='.github/workflows/pinned.yml',
        ref=decoded['ref'],commit_sha=decoded['head_sha'],step_sha256=decoded['step_sha256'],
        worker_job_guid=decoded['job_guid'],worker_request_id=decoded['request_id'],plan_guid=decoded['plan_guid'])
    permit=dict(binding,version=4,permit_id='nonresearch-only',attempt=1,issued_at=100,not_before=100,
        expires_at=200,execution_deadline=300)
    ledger=Ledger(tmp_path/'nonresearch-ledger.sqlite',{'owner':owner.public_key()},lambda _:None,clock=lambda:110)
    envelope=sign(permit,owner,'owner','ADAMON-P4V3-PERMIT');ledger.issue(envelope)
    partial=[]
    def controller(**kw):return NonresearchVerticalController(supervisor=supervisor,ledger=ledger,
        permit_id=permit['permit_id'],binding=binding,owner_key=owner,receipt_key=receipt,preserve_partial=partial.append,**kw)
    yield dict(controller=controller,ledger=ledger,partial=partial,receipt=receipt,supervisor=supervisor,
        rest=rest,binding=binding,envelope=envelope,message=message,worker=worker)
    if worker.poll() is None:worker.kill()
    worker.wait()
    os.close(record.pidfd);os.close(listener.pidfd)


def test_joined_assignment_permit_sealed_key_owned_process_injection_completion(setup):
    s=setup;c=s['controller']();result=c.run()
    assert result['completion']['status']=='COMPLETE'
    receipt=verify(result['receipt'],{'nonresearch-receipt':s['receipt'].public_key()},RECEIPT_DOMAIN)
    assert receipt['status']=='COMPLETE' and receipt['scope']=='NONRESEARCH_LOCAL_PROCESS_CANARY'
    assert c.child.exitcode==0 and s['partial']==[]
    assert s['ledger'].verify_chain()!='0'*64
    with pytest.raises(Denied,match='one-shot'):c.run()
    with pytest.raises(Denied,match='not issued'):s['controller']().run()


def test_joined_cancellation_kills_actual_owned_child_and_signed_partial(setup):
    c=setup['controller']()
    with pytest.raises(Denied,match='cancelled'):c.run(cancelled=lambda:True)
    assert c.child.exitcode==-9
    p=verify(setup['partial'][0],{'nonresearch-receipt':setup['receipt'].public_key()},RECEIPT_DOMAIN)
    assert p['status']=='PARTIAL' and p['phase']=='EXECUTING'
    assert setup['ledger'].verify_chain()!='0'*64


@pytest.mark.parametrize('mutation',[lambda s:s['binding'].update(run_attempt=3),
    lambda s:s['binding'].update(step_sha256='0'*64),lambda s:s['binding'].update(worker_request_id=999),
    lambda s:setattr(s['rest'],'live',False),lambda s:setattr(s['supervisor'].dispatch,'revoked',True)])
def test_job_identity_or_revocation_denied_before_owned_birth(setup,mutation):
    mutation(setup);c=setup['controller']()
    with pytest.raises(Denied):c.run()
    assert c.child is None and setup['partial'][0]['payload']['status']=='PARTIAL'


def test_signed_permit_corruption_denied(setup):
    e=dict(setup['envelope'],signature='0'*128)
    with pytest.raises(Denied,match='signature'):setup['ledger'].issue(e)


def test_bootstrap_failure_kills_child_and_preserves_partial(setup,monkeypatch):
    import infrastructure.t3.runtime.vertical as vertical
    def deny(*_,**__):raise OSError('synthetic memfd failure after real birth')
    monkeypatch.setattr(vertical.os,'memfd_create',deny)
    c=setup['controller']()
    with pytest.raises(OSError,match='memfd'):c.run()
    assert c.child.exitcode==-9 and setup['partial'][0]['payload']['phase']=='BOOTSTRAP'


def test_job_cancel_between_birth_and_injection_kills_child(setup,monkeypatch):
    import infrastructure.t3.runtime.vertical as vertical
    original=vertical.owned_record
    def birth(pid):
        record=original(pid);setup['rest'].live=False;return record
    monkeypatch.setattr(vertical,'owned_record',birth)
    c=setup['controller']()
    with pytest.raises(Denied,match='active Job'):c.run()
    assert c.child.exitcode==-9 and setup['partial'][0]['payload']['status']=='PARTIAL'


def test_research_fixed_step_still_unconditionally_denied(setup):
    d=setup['supervisor'].dispatch
    with pytest.raises(Denied,match='NO_APPROVED_EXECUTION_FREEZE'):
        setup['message']('WORKER','fixed_step_execute',dict(assignment_sha256=d.sha256,step_id=d.assignment['step_id']))


def test_independent_watchdog_supervisor_death_kills_real_owned_descendant(tmp_path):
    """Actual process death + pidfd signals; cgroup write remains synthetic.

    The test supervisor creates its canary child, hands its birth pidfd to the
    owner over SCM_RIGHTS, then is killed. The independently running watchdog
    retains that exact descriptor, not a PID supplied by workflow code.
    """
    import array
    import multiprocessing
    import socket
    import time
    from infrastructure.t3.runtime.watchdog import monitor
    def supervisor_child(stream_fd):
        stream=socket.socket(fileno=stream_fd)
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
        birth=owned_record(child.pid)
        stream.sendmsg([b'B'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[birth.pidfd]))])
        stream.close()
        time.sleep(60)
    parent,child=socket.socketpair()
    process=multiprocessing.get_context('fork').Process(target=supervisor_child,args=(child.fileno(),))
    process.start();child.close()
    data,ancillary,_,_=parent.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
    assert data==b'B'
    values=array.array('i');values.frombytes(ancillary[0][2]);canary_fd=values[0]
    supervisor_fd=os.pidfd_open(process.pid)
    rd,wr=os.pipe()
    killfd=os.memfd_create('explicit-synthetic-cgroup-write')
    marker=os.open(tmp_path/'partial-supervisor-death',os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600)
    try:
        process.kill();process.join(2)
        assert monitor(supervisor_fd,[canary_fd],killfd,rd,marker,time.monotonic()+2)=='SUPERVISOR_EXIT'
        import select
        poll=select.poll();poll.register(canary_fd,select.POLLIN)
        assert poll.poll(2000)
        assert (tmp_path/'partial-supervisor-death').read_text()=='SUPERVISOR_EXIT\n'
    finally:
        parent.close()
        for fd in (canary_fd,supervisor_fd,rd,wr,killfd,marker):os.close(fd)
        if process.is_alive():process.kill();process.join()


def test_birth_record_failure_does_not_leak_just_created_process(setup,monkeypatch):
    import infrastructure.t3.runtime.vertical as vertical
    def broken_record(_):raise OSError('synthetic pidfd capture failure after actual spawn')
    monkeypatch.setattr(vertical,'owned_record',broken_record)
    c=setup['controller']()
    with pytest.raises(OSError,match='pidfd capture'):c.run()
    assert c.child.exitcode==-9 and setup['partial'][0]['payload']['phase']=='BIRTH'


@pytest.mark.parametrize('field',['job_id','run_id','run_attempt','repository_id',
    'workflow_path','workflow_sha','ref','commit_sha','step_sha256','worker_job_guid',
    'worker_request_id','plan_guid','assignment_sha256'])
def test_every_full_assignment_tuple_field_bound_before_birth(setup,field):
    original=setup['binding'][field]
    setup['binding'][field]=original+1 if type(original) is int else 'wrong-'+original
    c=setup['controller']()
    with pytest.raises(Denied,match='assignment binding'):c.run()
    assert c.child is None and setup['partial'][0]['payload']['phase']=='ASSIGNMENT'
