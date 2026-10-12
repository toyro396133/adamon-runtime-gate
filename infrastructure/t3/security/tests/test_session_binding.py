"""Signed wrong workflow tuple is denied before TLS, even with same Job/digest."""
import os
import tempfile
import time
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.security.protocol import Denied,digest,sign
from infrastructure.t3.security.ledger import Ledger
from infrastructure.t3.security.session import SessionController
from infrastructure.t3.security.tests.test_actual_cancellation import record

@pytest.mark.parametrize('changed', ['workflow_sha','ref','commit_sha','repository_id','workflow_path','step_sha256','worker_job_guid','worker_request_id','plan_guid'])
def test_signed_wrong_assignment_tuple_with_same_job_and_raw_hash(changed):
    launcher=record(SimpleNamespace(pid=os.getpid()))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            now=int(time.time()); key=Ed25519PrivateKey.generate()
            request=dict(operation='NONRESEARCH_HANDSHAKE_ONLY')
            binding=dict(authority_sha256='a'*64,role='LIFE',subject='synthetic',job_id=7,run_id=8,run_attempt=1,repository_id=9,workflow_path='.github/workflows/gen06-t3-approved.yml',workflow_sha='c'*40,ref='refs/heads/planning',commit_sha='d'*40,step_sha256='e'*64,worker_job_guid='job-guid',worker_request_id=11,plan_guid='plan-guid',assignment_sha256='b'*64,client_spki_sha256='f'*64,request_sha256=digest(request))
            a=dict(job_id=7,run_id=8,run_attempt=1,repository_id=9,repository='o/r',workflow_ref='o/r/.github/workflows/gen06-t3-approved.yml@refs/heads/planning',workflow_sha='c'*40,ref='refs/heads/planning',head_sha='d'*40,step_sha256='e'*64,job_guid='job-guid',request_id=11,plan_guid='plan-guid')
            binding[changed]=binding[changed]+1 if type(binding[changed]) is int else 'wrong'
            ledger=Ledger(tmp+'/ledger.sqlite',{'owner':key.public_key()},lambda _:None)
            permit=dict(binding,version=4,permit_id='wrong-tuple',attempt=1,issued_at=now,not_before=now,expires_at=now+90,execution_deadline=now+120)
            ledger.issue(sign(permit,key,'owner','ADAMON-P4V3-PERMIT'))
            dispatch=SimpleNamespace(assignment=a,sha256='b'*64,revoked=False,authorized=True,acknowledged=True)
            cleanup=[]
            def preserve(reason):
                with open(tmp+'/partial','x') as f:f.write(reason)
            supervisor=SimpleNamespace(dispatch=dispatch,correlate=lambda _:None,revoke=lambda reason:cleanup.append(reason))
            controller=SessionController(supervisor=supervisor,launcher=launcher,ledger=ledger,permit_id='wrong-tuple',binding=binding,request=request,context=None,ca=None,oid=None,expected_spki='f'*64,kill_job=lambda:cleanup.append('kill'),preserve_partial=preserve)
            with pytest.raises(Denied,match='permit/assignment identity mismatch'):
                controller.open(None)
            assert cleanup==['SESSION_FAILED','kill']
            with open(tmp+'/partial') as f:assert f.read()=='SESSION_FAILED'
            with ledger.connect() as db:assert db.execute('SELECT state FROM permits').fetchone()[0]=='ISSUED'
    finally:os.close(launcher.pidfd)


def test_session_keeps_deep_canonical_request_and_binding_snapshot():
    launcher=record(SimpleNamespace(pid=os.getpid()))
    request={'operation':'NONRESEARCH_HANDSHAKE_ONLY','nested':{'version_id':'original'}}
    binding={'client_spki_sha256':'a'*64,'request_sha256':digest(request),'nested':{'source':'pinned'}}
    try:
        controller=SessionController(supervisor=None,launcher=launcher,ledger=None,permit_id='snapshot',
            binding=binding,request=request,context=None,ca=None,oid=None,expected_spki='a'*64,
            kill_job=lambda:None,preserve_partial=lambda _:None)
        request['nested']['version_id']='changed-after-construction'
        binding['nested']['source']='changed-after-construction'
        assert controller.request['nested']['version_id']=='original'
        assert controller.binding['nested']['source']=='pinned'
        returned=controller.request;returned['nested']['version_id']='changed-through-getter'
        assert controller.request['nested']['version_id']=='original'
    finally:os.close(launcher.pidfd)
