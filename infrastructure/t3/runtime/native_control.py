"""Local descriptor-only lifecycle control. Does not spawn or authorize a VMM."""
import os
import select
import signal


class NativeJobControl:
    """Descriptors originate from supervisor clone3/cgroup setup, never RPC.

    Kernel cgroup.kill terminates descendants even when VMM forks. Supplied
    evidence/credential capabilities are private broker objects. A separately
    reviewed host watchdog must independently call kill when supervisor dies.
    """
    def __init__(self, worker_pidfd, vmm_pidfd, cgroup_kill_fd, subject_kill_fd, credential_scope,
                 evidence_scope):
        for fd in (worker_pidfd, vmm_pidfd, cgroup_kill_fd, subject_kill_fd):
            if type(fd) is not int or fd < 0:
                raise ValueError('supervisor descriptor required')
            os.fstat(fd)
            os.set_inheritable(fd, False)
        self.worker_pidfd, self.vmm_pidfd = worker_pidfd, vmm_pidfd
        self.kill_fd = cgroup_kill_fd
        self.subject_kill_fd = subject_kill_fd
        self.credentials, self.evidence = credential_scope, evidence_scope
        self.killed = False
        self.cleanup_failed = False

    @staticmethod
    def _dead(fd):
        poll = select.poll()
        poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poll.poll(0))

    def check_live(self):
        # Worker owns the Job; VMM exit is interpreted by exited()/exit status.
        return not (self.killed or self.cleanup_failed) and not self._dead(self.worker_pidfd)

    def exited(self):
        return self._dead(self.vmm_pidfd)

    def exit_successful(self):
        info = os.waitid(os.P_PIDFD, self.vmm_pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return bool(info and info.si_code == os.CLD_EXITED and info.si_status == 0
                    and self.evidence.guest_completion_authenticated())

    def kill_job_cgroup(self):
        if not self.killed:
            self._kill_scope(self.kill_fd, (self.vmm_pidfd, self.worker_pidfd))
            self.killed = True  # Only after all attempted cleanup operations succeeded.

    def _kill_scope(self, kill_fd, known_pidfds):
        errors = []
        try:
            os.lseek(kill_fd, 0, os.SEEK_SET)
            if os.write(kill_fd, b'1') != 1:
                raise OSError('cgroup.kill short write')
        except OSError as exc:
            errors.append(exc)
        finally:
            # A broken cgroup descriptor must not skip the independent known-
            # process signals. Keep attempting other pidfds after one fails.
            for fd in known_pidfds:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    errors.append(exc)
        if errors:
            self.cleanup_failed = True
            raise ExceptionGroup('cleanup incomplete; descendants require host watchdog', errors)

    def revoke_credentials(self):
        self.credentials.revoke()

    def stop_subject_scope(self):
        # Worker survives long enough to report fixed-step completion; supervisor
        # tears down the full Job after its completion acknowledgement.
        self._kill_scope(self.subject_kill_fd, (self.vmm_pidfd,))

    def preserve_partial(self, reason):
        self.evidence.preserve_partial(reason)

    def seal_complete(self):
        self.evidence.seal_complete()
