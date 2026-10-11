import unittest
from infrastructure.t3.security.protocol import Denied
from infrastructure.t3.security.supervisor import Supervisor, exact

class CorrelationTests(unittest.TestCase):
    def fixture(self):
        expected=dict(workflow_ref='r/w@ref',workflow_sha='a'*40,ref='ref',head_sha='b'*40,run_id=2,run_attempt=1,repository='synthetic',runner_id=3)
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
