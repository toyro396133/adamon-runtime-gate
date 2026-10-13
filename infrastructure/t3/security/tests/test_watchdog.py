import unittest
from infrastructure.t3.security.watchdog import JobWatchdog, WatchdogFailure

class Tests(unittest.TestCase):
    def setUp(self):
        self.now=[0]
        self.events=[]
        self.states=dict(worker=True,launcher=True,assignment=True,permit=True)
        self.w=JobWatchdog(worker_alive=lambda:self.states['worker'],launcher_alive=lambda:self.states['launcher'],
                           assignment_active=lambda:self.states['assignment'],permit_live=lambda:self.states['permit'],
                           revoke=lambda reason:self.events.append('revoke:'+reason),
                           kill_cgroup=lambda:self.events.append('kill'),
                           preserve_partial=lambda reason:self.events.append('preserve:'+reason),
                           deadline=100,clock=lambda:self.now[0])
    def test_good_heartbeat(self):
        self.now[0]=20
        self.assertIsNone(self.w.poll());self.assertEqual(self.events,[])
    def test_failed_signals_are_terminal(self):
        for key,reason in [('worker','WORKER_EXIT'),('launcher','LAUNCHER_EXIT'),('assignment','ASSIGNMENT_LOST'),('permit','PERMIT_REVOKED')]:
            self.setUp();self.states[key]=False
            self.assertEqual(self.w.poll(),reason)
            self.assertEqual(self.w.poll(),reason)
            self.assertEqual(self.events,['revoke:'+reason,'kill','preserve:'+reason])
    def test_timeout_and_cancel(self):
        self.now[0]=60;self.assertEqual(self.w.poll(),'LEASE_EXPIRED')
        self.setUp();self.now[0]=100;self.assertEqual(self.w.poll(),'JOB_DEADLINE')
        self.setUp();self.assertEqual(self.w.poll(cancelled=True),'JOB_CANCELLED')
    def test_error_fail_closed(self):
        self.w.assignment_active=lambda:1/0
        self.assertEqual(self.w.poll(),'VERIFICATION_UNAVAILABLE')
        self.assertEqual(self.events[1],'kill')
    def test_kill_runs_despite_revoke_exception(self):
        self.w.revoke=lambda _:(_ for _ in ()).throw(RuntimeError('offline'))
        with self.assertRaises(WatchdogFailure):self.w.poll(cancelled=True)
        self.assertEqual(self.events,['kill','preserve:JOB_CANCELLED'])
        self.assertEqual(self.w.poll(),'JOB_CANCELLED')
    def test_invalid_config(self):
        with self.assertRaises(WatchdogFailure):JobWatchdog(worker_alive=lambda:True,launcher_alive=lambda:True,assignment_active=lambda:True,permit_live=lambda:True,
           revoke=lambda _:None,kill_cgroup=lambda:None,preserve_partial=lambda _:None,deadline=100,clock=lambda:0,lease_seconds=61)

if __name__=='__main__': unittest.main()
