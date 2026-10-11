"""Actual Linux pidfd fallback + retained partial bytes; NOT cgroup isolation proof."""
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest
from infrastructure.t3.runtime.native_control import NativeJobControl
from infrastructure.t3.security.watchdog import JobWatchdog, WatchdogFailure


def test_failed_cgroup_write_still_kills_real_owned_processes_and_preserves_partial(tmp_path):
    processes = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']) for _ in range(2)]
    pidfds = [os.pidfd_open(p.pid) for p in processes]
    # Intentionally not a cgroup: force write failure and exercise kernel pidfd fallback.
    broken_kill = os.open('/dev/null', os.O_RDONLY)
    partial = tmp_path / 'partial.bin'
    partial.write_bytes(b'nonresearch partial bytes\x00\xff')
    before = partial.read_bytes()
    events = []
    class Credentials:
        def revoke(self): events.append('REVOKED')
    class Evidence:
        def preserve_partial(self, reason):
            assert partial.read_bytes() == before
            (tmp_path / 'reason.txt').write_text(reason)
            events.append('PRESERVED')
    control = NativeJobControl(pidfds[0], pidfds[1], broken_kill, broken_kill, Credentials(), Evidence())
    watchdog = JobWatchdog(worker_alive=control.check_live, launcher_alive=lambda:True,
        assignment_active=lambda:True, permit_live=lambda:True,
        revoke=lambda reason:control.revoke_credentials(), kill_cgroup=control.kill_job_cgroup,
        preserve_partial=control.preserve_partial, deadline=time.monotonic()+10)
    try:
        with pytest.raises(WatchdogFailure, match='cleanup failed'):
            watchdog.poll(cancelled=True)
        assert [p.wait(timeout=3) for p in processes] == [-9, -9]
        assert events == ['REVOKED', 'PRESERVED']
        assert control.cleanup_failed and not control.killed
        assert not control.check_live()
        assert partial.read_bytes() == before
        assert (tmp_path / 'reason.txt').read_text() == 'JOB_CANCELLED'
    finally:
        for p in processes:
            if p.poll() is None: p.kill();p.wait()
        for fd in pidfds+[broken_kill]:os.close(fd)
