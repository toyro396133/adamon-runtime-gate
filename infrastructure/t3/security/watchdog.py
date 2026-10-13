"""Fail-closed synthetic policy for supervisor-owned GitHub Job watchdog.

No actual runner/process enrollment is implemented here. All observed signals
must come from trusted, injected supervisor capabilities, never workflow data.
"""
import threading
import time


class WatchdogFailure(RuntimeError):
    pass


class JobWatchdog:
    """Single-job, one-shot cancellation policy. Research execution remains blocked."""
    def __init__(self, *, worker_alive, launcher_alive, assignment_active,
                 permit_live, revoke, kill_cgroup, preserve_partial,
                 deadline, clock=time.monotonic, lease_seconds=60):
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 60:
            raise WatchdogFailure('invalid lease policy')
        if type(deadline) not in (int, float) or deadline <= clock():
            raise WatchdogFailure('invalid job deadline')
        self.worker_alive = worker_alive
        self.launcher_alive = launcher_alive
        self.assignment_active = assignment_active
        self.permit_live = permit_live
        self.revoke = revoke
        self.kill_cgroup = kill_cgroup
        self.preserve_partial = preserve_partial
        self.deadline = deadline
        self.clock = clock
        self.lease_seconds = lease_seconds
        self.last_confirmed = clock()
        self.terminal_reason = None
        self.lock = threading.RLock()

    def _stop(self, reason):
        if self.terminal_reason is not None:
            return self.terminal_reason
        self.terminal_reason = reason
        errors = []
        for action in (lambda: self.revoke(reason), self.kill_cgroup,
                       lambda: self.preserve_partial(reason)):
            try:
                action()
            except BaseException as exc:
                errors.append(type(exc).__name__)
        if errors:
            raise WatchdogFailure('cleanup failed: ' + ','.join(errors))
        return reason

    def poll(self, *, cancelled=False):
        """One supervisor heartbeat, never an execution authorization."""
        with self.lock:
            if self.terminal_reason is not None:
                return self.terminal_reason
            now = self.clock()
            if cancelled:
                return self._stop('JOB_CANCELLED')
            if now >= self.deadline:
                return self._stop('JOB_DEADLINE')
            if now - self.last_confirmed >= self.lease_seconds:
                return self._stop('LEASE_EXPIRED')
            try:
                status = (self.worker_alive(), self.launcher_alive(),
                          self.assignment_active(), self.permit_live())
            except BaseException:
                return self._stop('VERIFICATION_UNAVAILABLE')
            for active, reason in zip(status, ('WORKER_EXIT','LAUNCHER_EXIT',
                                              'ASSIGNMENT_LOST','PERMIT_REVOKED')):
                if active is not True:
                    return self._stop(reason)
            self.last_confirmed = now
            return None

class EnrolledJobWatchdog:
    """Concrete retained-process/REST/ledger heartbeat, no execution capability."""
    def __init__(self, *, supervisor, launcher, ledger, permit_id, session,
                 kill_cgroup, preserve_partial, deadline, interval=5):
        from .process import ProcessRecord
        if not isinstance(launcher,ProcessRecord) or not 0<interval<=10:
            raise WatchdogFailure('retained launcher and bounded heartbeat required')
        self.supervisor,self.launcher,self.ledger=supervisor,launcher,ledger
        self.permit_id,self.session,self.interval=permit_id,session,interval
        def alive(record):
            record.verify();return True
        def assignment():
            dispatch=supervisor.dispatch
            if dispatch is None or dispatch.revoked: return False
            supervisor.correlate(dispatch.assignment)
            ledger.renew(permit_id,session,verified_job_live=True)
            return True
        self.policy=JobWatchdog(worker_alive=lambda:alive(supervisor._worker()),
            launcher_alive=lambda:alive(launcher),assignment_active=assignment,
            permit_live=lambda:ledger.session_live(permit_id,session),
            revoke=lambda reason:ledger.end_session(permit_id,session,reason),
            kill_cgroup=kill_cgroup,preserve_partial=preserve_partial,deadline=deadline)
        self.cancelled=threading.Event()
    def cancel(self):
        self.cancelled.set()
    def run(self):
        while True:
            reason=self.policy.poll(cancelled=self.cancelled.is_set())
            if reason is not None:return reason
            self.cancelled.wait(self.interval)
