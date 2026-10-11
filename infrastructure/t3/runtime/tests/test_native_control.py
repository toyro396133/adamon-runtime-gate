"""Local FD readiness doubles; no cgroup, pidfd signal or VM is operated."""
import os
import tempfile
import unittest
from unittest.mock import patch
from infrastructure.t3.runtime.native_control import NativeJobControl


class Scope:
    def revoke(self): pass
    def preserve_partial(self, reason): pass
    def seal_complete(self): pass
    def guest_completion_authenticated(self): return True


class Tests(unittest.TestCase):
    def test_descriptors_are_not_inherited(self):
        a,b=os.pipe(); c,d=os.pipe()
        try:
            with tempfile.TemporaryFile() as f:
                controller=NativeJobControl(a,c,f.fileno(),f.fileno(),Scope(),Scope())
                self.assertFalse(os.get_inheritable(a))
                self.assertTrue(controller.check_live())
                self.assertFalse(controller.exited())
                os.close(b); b=-1
                self.assertFalse(controller.check_live())
        finally:
            for fd in (a,b,c,d):
                if fd>=0: os.close(fd)

    def test_kill_is_idempotent_with_mocked_signals(self):
        a,b=os.pipe(); c,d=os.pipe()
        try:
            with tempfile.TemporaryFile() as f:
                controller=NativeJobControl(a,c,f.fileno(),f.fileno(),Scope(),Scope())
                with patch('signal.pidfd_send_signal') as fake:
                    controller.kill_job_cgroup(); controller.kill_job_cgroup()
                    self.assertEqual(fake.call_count,2)
                f.seek(0); self.assertEqual(f.read(),b'1')
                self.assertFalse(controller.check_live())
        finally:
            for fd in (a,b,c,d): os.close(fd)

    def test_broken_cgroup_still_attempts_both_known_processes(self):
        a,b=os.pipe(); c,d=os.pipe()
        try:
            with tempfile.TemporaryFile() as f:
                controller=NativeJobControl(a,c,f.fileno(),f.fileno(),Scope(),Scope())
                with patch('os.lseek',side_effect=OSError('synthetic cgroup failure')):
                    with patch('signal.pidfd_send_signal') as fake:
                        with self.assertRaises(ExceptionGroup):controller.kill_job_cgroup()
                        self.assertEqual([x.args[0] for x in fake.call_args_list],[c,a])
                self.assertTrue(controller.cleanup_failed)
                self.assertFalse(controller.check_live())
                self.assertFalse(controller.killed)
        finally:
            for fd in (a,b,c,d):os.close(fd)

    def test_success_scope_failure_never_signals_worker(self):
        a,b=os.pipe(); c,d=os.pipe()
        try:
            with tempfile.TemporaryFile() as f:
                controller=NativeJobControl(a,c,f.fileno(),f.fileno(),Scope(),Scope())
                with patch('os.write',side_effect=OSError('synthetic subject failure')):
                    with patch('signal.pidfd_send_signal') as fake:
                        with self.assertRaises(ExceptionGroup):controller.stop_subject_scope()
                        self.assertEqual([x.args[0] for x in fake.call_args_list],[c])
        finally:
            for fd in (a,b,c,d):os.close(fd)


if __name__=='__main__': unittest.main()
