import unittest
from infrastructure.t3.security.protocol import Denied
from infrastructure.t3.security.supervisor import Supervisor, exact

class CorrelationTests(unittest.TestCase):
    def fixture(self):
        expected=dict(workflow_ref='r/w@ref',workflow_sha='a'*40,ref='ref',head_sha='b'*40,run_id=2,run_attempt=1,repository='synthetic',repository_id=99,runner_id=3)
        assignment=dict(expected,job_id=4)
        class REST:
            def get_run(self,*_): return dict(expected)
            def list_jobs(self,*_): return [dict(assignment,status='in_progress')]
        s=object.__new__(Supervisor);s.expected=expected;s.rest=REST()
        return s,assignment
    def test_exact_scalar_types(self):
        self.assertFalse(exact(True,1)); self.assertFalse(exact(False,0))
    def test_rest_single_numeric_job(self):
        s,a=self.fixture(); self.assertEqual(s.correlate(a)['job_id'],4)
    def test_public_guid_or_boolean_cannot_be_numeric_job(self):
        for value in (True,'4','a-b-c'):
            s,a=self.fixture();a['job_id']=value
            with self.assertRaises(Denied):s.correlate(a)
    def test_ambiguous_or_missing_job_denied(self):
        for jobs in ([],[{},{}]):
            s,a=self.fixture();s.rest.list_jobs=lambda *_:jobs
            with self.assertRaises(Denied):s.correlate(a)
    def test_wrong_workflow_sha(self):
        s,a=self.fixture();a['workflow_sha']='c'*40
        with self.assertRaises(Denied):s.correlate(a)
    def test_listener_private_endpoint_cannot_issue_worker_commands(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import threading
        s=object.__new__(Supervisor)
        s.listener=Mock()
        s.dispatch=SimpleNamespace(revoked=False,acknowledged=False,
                                   raw='fixed-raw',sha256='a'*64,
                                   worker=Mock(),assignment=dict(step_id='step',marker='ADAMON_P4_FIXED_LAUNCH_V4'))
        s.lock=threading.RLock()
        s._private_context=threading.local()
        s._private_context.role='LISTENER'
        s.request_ids=set()
        for index,operation in enumerate(('worker_ack','authorize_assignment','fixed_step_execute')):
            with self.subTest(operation=operation), self.assertRaises(Denied):
                s.handle_private_message('LISTENER',
                    {'request_id':str(index),'operation':operation,
                     'payload':{'assignment_sha256':'a'*64,'raw_assignment':'fixed-raw',
                                'step_id':'step'}},[])
        self.assertFalse(s.dispatch.acknowledged)
        self.assertFalse(getattr(s.dispatch,'authorized',False))

    def test_direct_public_message_cannot_enroll(self):
        s,a=self.fixture()
        import threading
        s.lock=threading.RLock();s._private_context=threading.local()
        with self.assertRaises(Denied):s.handle_private_message('LISTENER',{},[])

class WorkerLifetimeTests(unittest.TestCase):
    def test_wait_reports_actual_exit_not_spawn_ack(self):
        import os, subprocess, sys
        from types import SimpleNamespace
        from infrastructure.t3.security.supervisor import WorkerCompletion
        if not hasattr(os,'pidfd_open'): self.skipTest('pidfd unavailable')
        child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(.05); raise SystemExit(7)'])
        fd=os.pidfd_open(child.pid)
        reasons=[]
        try:
            self.assertEqual(WorkerCompletion(SimpleNamespace(pidfd=fd),reasons.append).wait(),7)
            self.assertEqual(reasons,['worker_exit'])
        finally:
            os.close(fd);child.wait()

class AssignmentBindingTests(unittest.TestCase):
    def test_check_id_not_job_id(self):
        from infrastructure.t3.security.supervisor import RunnerAssignmentBinder
        class Rest:
            def list_jobs(self,*_): return [dict(job_id=81,check_run_id=62,runner_id=4,status='in_progress')]
        binder=RunnerAssignmentBinder(lambda _:dict(run_id=2,run_attempt=1,check_run_id=62),Rest(),runner_id=4)
        self.assertEqual(binder({})['job_id'],81)
        self.assertEqual(binder({})['runner_id'],4)
    def test_wrong_runner_check_or_ambiguous_denied(self):
        from infrastructure.t3.security.supervisor import RunnerAssignmentBinder
        for jobs in ([],[dict(job_id=81,check_run_id=62,runner_id=5,status='in_progress')],
                     [dict(job_id=81,check_run_id=62,runner_id=4,status='in_progress')]*2):
            class Rest:
                def list_jobs(self,*_): return jobs
            with self.assertRaises(Denied):
                RunnerAssignmentBinder(lambda _:dict(run_id=2,run_attempt=1,check_run_id=62),Rest(),runner_id=4)({})

class PreSpawnIdentityTests(unittest.TestCase):
    fixture = CorrelationTests.fixture
    def test_rest_check_run_cannot_change_after_binding(self):
        s,a=self.fixture();a['check_run_id']=50
        s.rest.list_jobs=lambda *_:[dict(a,status='in_progress',check_run_id=51)]
        with self.assertRaises(Denied):s.correlate(a)

    def test_optional_owner_workflow_blob_pin_is_enforced(self):
        s,a=self.fixture();s.expected['workflow_blob_sha']='c'*40
        s.rest.get_run=lambda *_:dict(a,workflow_blob_sha='d'*40)
        with self.assertRaises(Denied):s.correlate(a)

    def test_wrong_source_rejected_before_worker_factory(self):
        import hashlib,json,threading
        from unittest.mock import Mock
        s,a=self.fixture();a['workflow_sha']='d'*40
        s.listener=Mock();s.dispatch=None;s.request_ids=set()
        s.lock=threading.RLock();s._private_context=threading.local();s._private_context.role='LISTENER'
        s.validate_assignment=lambda _:a;s.spawn_worker=Mock()
        raw=json.dumps({'closed':'synthetic'})
        with self.assertRaises(Denied):
            s.handle_private_message('LISTENER',dict(request_id='pre-spawn',operation='listener_snapshot_spawn',
                payload=dict(raw_assignment=raw,assignment_sha256=hashlib.sha256(raw.encode()).hexdigest())),[0,1])
        s.spawn_worker.assert_not_called()

class MalformedPrivateChannelTests(unittest.TestCase):
    def test_decode_failure_revokes_without_a_well_formed_request(self):
        import socket,struct
        from unittest.mock import Mock
        from infrastructure.t3.security.bridge import handle
        parent,child=socket.socketpair()
        supervisor=Mock()
        try:
            child.sendall(struct.pack('!I',0))
            handle(parent,'WORKER',supervisor)
            supervisor.revoke.assert_called_once_with('bridge_failure')
            supervisor.handle_private_message.assert_not_called()
        finally:
            parent.close();child.close()

class PermitTrustAnchorTests(unittest.TestCase):
    def test_owner_key_mapping_is_snapshot_and_read_only(self):
        import tempfile
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from infrastructure.t3.security.ledger import Ledger
        trusted=Ed25519PrivateKey.generate().public_key()
        owners={'owner':trusted}
        with tempfile.TemporaryDirectory() as path:
            ledger=Ledger(path+'/ledger.sqlite',owners,lambda _:None)
            owners['owner']=Ed25519PrivateKey.generate().public_key()
            self.assertIs(ledger.keys['owner'],trusted)
            with self.assertRaises(TypeError):ledger.keys['owner']=owners['owner']

class BootstrapPermitBindingTests(unittest.TestCase):
    def test_readonly_key_delivery_check_rejects_mismatch_and_consumed_permit(self):
        import tempfile
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from infrastructure.t3.security.ledger import Ledger
        from infrastructure.t3.security.protocol import sign
        owner=Ed25519PrivateKey.generate()
        binding=dict(authority_sha256='a'*64,role='LIFE',subject='synthetic',
                     deployment_sha256='b'*64,client_spki_sha256='c'*64,
                     source_sha256='d'*64,fixture_sha256='e'*64)
        p=dict(binding,version=4,permit_id='prepared-key-only',attempt=1,
               issued_at=100,not_before=100,expires_at=150,execution_deadline=180)
        with tempfile.TemporaryDirectory() as path:
            ledger=Ledger(path+'/ledger.sqlite',{'owner':owner.public_key()},lambda _:None,clock=lambda:110)
            ledger.issue(sign(p,owner,'owner','ADAMON-P4V3-PERMIT'))
            self.assertEqual(ledger.require_issued(p['permit_id'],binding)['permit_id'],p['permit_id'])
            self.assertFalse(ledger.session_live(p['permit_id'],'not-granted'))
            with self.assertRaises(Denied):ledger.require_issued(p['permit_id'],dict(binding,client_spki_sha256='f'*64))
            with self.assertRaises(Denied):ledger.require_issued(p['permit_id'],{'role':'LIFE'})
            ledger.consume(p['permit_id'],binding,'proof-session')
            with self.assertRaises(Denied):ledger.require_issued(p['permit_id'],binding)

    def test_key_preparation_refuses_unguarded_birth_before_key_generation(self):
        from infrastructure.t3.security.supervisor import prepare_deployed_launcher_credential
        from infrastructure.t3.runtime.deployment import BirthOrder
        with self.assertRaises(Denied):
            prepare_deployed_launcher_credential(supervisor=None,ca=None,record=None,binding={},request={},birth_order=BirthOrder())

class ClosedDeploymentBuilderTests(unittest.TestCase):
    def test_unsigned_deployment_rejected_before_factory_or_identity_use(self):
        from infrastructure.t3.security.supervisor import connect_deployed_supervisor
        from infrastructure.t3.runtime.microvm import Blocked
        with self.assertRaises(Blocked):
            connect_deployed_supervisor(listener=None,native_factory=None,
                repository='owner/repo',owner_token_provider=None,
                approved_identity={},cleanup=None,deployment_envelope={'payload':{}},
                deployment_owner_public_key=bytes(32),image_descriptors={},clock=lambda:100)

    def test_mutable_image_rejected_before_native_factory_birth(self):
        import os,hashlib
        from infrastructure.t3.security.native import NativeProcessFactory
        from infrastructure.t3.security.supervisor import DeploymentBoundWorkerSpawner
        from infrastructure.t3.runtime.deployment import Deployment,IMAGES
        from infrastructure.t3.runtime.tests.test_deployment import payload,signed
        from infrastructure.t3.runtime.microvm import Blocked
        raw=b'NONRESEARCH-CONFIG-ONLY';sha=hashlib.sha256(raw).hexdigest()
        p=payload();p['images']={n:sha for n in IMAGES};env,key=signed(p)
        d=Deployment.verify(env,key,lambda:100)
        roles={role:dict(exe_fd=0,sha256='b'*64,cgroup_fd=0,cgroup='0::/synthetic',
                        uid=p['identities'][role]['uid'],gid=p['identities'][role]['gid'])
               for role in ('LISTENER','WORKER','LAUNCHER')}
        # No native call: verifier must reject writable bytes first.
        factory=NativeProcessFactory(None,roles)
        fd=os.memfd_create('mutable-rejection',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            os.write(fd,raw)
            with self.assertRaises(Blocked):
                DeploymentBoundWorkerSpawner(factory,d,{n:fd for n in IMAGES},lambda:100)
        finally:os.close(fd)

class BootstrapSubjectProjectionTests(unittest.TestCase):
    def test_exact_frozen_start_selectors_and_wrong_subject_rejected(self):
        from infrastructure.t3.security.supervisor import validate_bootstrap_request_binding
        common=dict(authority_sha256='a'*64,source_sha256='b'*64,environment_sha256='c'*64)
        for operation,role,selector in [('life.execute','LIFE','case'),('micro.execute','MICRO','control_id'),('audit.verify','AUDIT','case'),('audit.verify_micro','AUDIT','control_id')]:
            binding=dict(common,role=role,subject='synthetic')
            request=dict(common,role=role,operation=operation,**{selector:'synthetic'})
            validate_bootstrap_request_binding(binding,request)
            request[selector]='another-subject'
            with self.assertRaises(Denied):validate_bootstrap_request_binding(binding,request)
    def test_status_or_arbitrary_shell_cannot_mint_bootstrap_credentials(self):
        from infrastructure.t3.security.supervisor import validate_bootstrap_request_binding
        for operation in ('life.status','micro.cancel','shell','command'):
            with self.assertRaises(Denied):validate_bootstrap_request_binding({},dict(operation=operation))
