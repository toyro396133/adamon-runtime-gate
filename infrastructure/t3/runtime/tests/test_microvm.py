"""Synthetic supervisor/API doubles only: no VMM/KVM/Job is started."""
import unittest
from infrastructure.t3.runtime.microvm import *


class Fake:
    def __init__(self):
        self.operations=[]; self.events=[]; self.live=True; self.success=True
    def put(self, endpoint, value): self.operations.append((endpoint,value))
    def check_live(self, *args): return self.live
    def exited(self): return True
    def exit_successful(self): return self.success
    def kill_job_cgroup(self): self.events.append('kill')
    def stop_subject_scope(self): self.events.append('stop-subject')
    def preserve_partial(self, reason): self.events.append('preserve')
    def revoke_credentials(self): self.events.append('revoke')
    def seal_complete(self): self.events.append('seal')
    def execute(self, attestation, timeout=30): pass
    def poll_completion(self, timeout): return {'synthetic_signed_completion':True}


class Tests(unittest.TestCase):
    def build(self, role='LIFE', preflight=True):
        f=Fake(); s=Subject(role,'closed-subject','a'*64,'b'*64)
        f.binding=dict(role=role,subject=s.subject,source_sha256=s.source_sha256,fixture_sha256=s.fixture_sha256)
        r=Resources('c'*64,'d'*64,'e'*64,True,True,True,True,True,True,preflight)
        l=Lifecycle([s],dict(binary='c'*64,kernel='d'*64,root='e'*64),f,f,f,r,clock=lambda:1,guest=f)
        return l,f,s
    def test_public_entry_always_blocked(self):
        with self.assertRaises(Blocked): execute_research({'permit':'anything'})
    def test_fixed_local_configuration(self):
        l,f,s=self.build(); self.assertEqual(l.run_trusted(s,10),'COMPLETE')
        self.assertEqual(len(f.operations),6)
        self.assertEqual(f.operations[-1],('/actions',{'action_type':'InstanceStart'}))
        self.assertEqual(f.events,['seal','revoke','stop-subject'])
        with self.assertRaises(Blocked): l.run_trusted(s,10)
    def test_audit_original_drive_readonly(self):
        l,f,s=self.build('AUDIT'); l.run_trusted(s,10)
        self.assertTrue(dict(f.operations)['/drives/evidence']['is_read_only'])
    def test_unregistered_subject_denied(self):
        l,f,s=self.build()
        with self.assertRaises(Blocked): l.run_trusted(Subject('LIFE','other','a'*64,'b'*64),10)
        self.assertEqual(f.operations,[]); self.assertEqual(f.events,['revoke','kill','preserve'])
    def test_absent_native_preflight_no_start(self):
        l,f,s=self.build(preflight=False)
        with self.assertRaises(Blocked): l.run_trusted(s,10)
        self.assertEqual(f.operations,[])
    def test_cancel_before_configure(self):
        l,f,s=self.build()
        with self.assertRaises(Blocked): l.run_trusted(s,10,cancelled=lambda:True)
        self.assertEqual(f.operations,[])
    def test_cancel_before_start(self):
        l,f,s=self.build(); n=[0]
        def cancel(): n[0]+=1; return n[0]==6
        with self.assertRaises(Blocked): l.run_trusted(s,10,cancelled=cancel)
        self.assertNotIn('/actions',dict(f.operations)); self.assertIn('preserve',f.events)
    def test_revocation_no_start(self):
        l,f,s=self.build(); f.live=False
        with self.assertRaises(Blocked): l.run_trusted(s,10)
        self.assertEqual(f.operations,[])
    def test_wrong_pin_no_start(self):
        l,f,s=self.build(); l.pins['kernel']='f'*64
        with self.assertRaises(Blocked): l.run_trusted(s,10)
        self.assertEqual(f.operations,[])
    def test_failed_guest_partial_only(self):
        l,f,s=self.build(); f.success=False
        with self.assertRaises(Blocked): l.run_trusted(s,10)
        self.assertNotIn('seal',f.events); self.assertIn('preserve',f.events)
    def test_deadline_bounded(self):
        for deadline in (0,300000):
            l,f,s=self.build()
            with self.assertRaises(Blocked): l.run_trusted(s,deadline)
            self.assertEqual(f.operations,[])
    def test_kill_even_when_revoke_throws(self):
        l,f,s=self.build(preflight=False)
        def broken(): raise RuntimeError('fake revoke')
        f.revoke_credentials=broken
        with self.assertRaises(RuntimeError): l.run_trusted(s,10)
        self.assertEqual(f.events,['kill','preserve'])
    def test_remote_socket_forbidden(self):
        sock=socket.socket(socket.AF_INET)
        try:
            with self.assertRaises(Blocked): UnixHTTP(sock)
        finally: sock.close()
    def test_missing_signed_completion_denied(self):
        l,f,s=self.build(); f.poll_completion=lambda timeout:None
        with self.assertRaises(Blocked): l.run_trusted(s,10)
        self.assertNotIn('seal',f.events)


if __name__=='__main__': unittest.main()
