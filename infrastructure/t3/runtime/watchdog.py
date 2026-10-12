"""Independent native-descriptor host watchdog. No research/VM is launched."""
import os
import select
import signal
import time


def monitor(supervisor_pidfd, process_pidfds, cgroup_kill_fd, control_fd,
            partial_marker_fd, deadline, clock=time.monotonic, cgroup_events_fd=None):
    """Run in dedicated trusted supervisor process outside the Job cgroup.

    STOP means successful Job cleanup already acknowledged; otherwise supervisor
    death, revocation/EOF, timeout, or malformed input forces kill. Marker fd is
    append-only trusted evidence capability; failure never skips process kill.
    Caller must attest watchdog UID/cgroup separately before research enablement.
    """
    poll=select.poll()
    poll.register(supervisor_pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
    poll.register(control_fd,select.POLLIN|select.POLLHUP|select.POLLERR)
    reason=None
    while reason is None:
        remaining=deadline-clock()
        if remaining<=0: reason='WATCHDOG_DEADLINE'; break
        for fd, event in poll.poll(min(1000,max(1,int(remaining*1000)))):
            if fd==supervisor_pidfd:
                reason='SUPERVISOR_EXIT'; break
            # Closed protocol single byte. No command, PID, path, renewed
            # deadline or authorization is accepted from this channel.
            value=os.read(control_fd,2)
            if value==b'S':
                # A supervisor acknowledgement is not proof descendants died.
                # Require both original pidfds and kernel cgroup population.
                all_dead=True
                for pidfd in process_pidfds:
                    check=select.poll();check.register(pidfd,select.POLLIN)
                    if not check.poll(0):all_dead=False
                empty=False
                if cgroup_events_fd is not None:
                    try:
                        raw=os.pread(cgroup_events_fd,4096,0)
                        empty=b'populated 0\n' in raw and b'populated 1' not in raw
                    except OSError:pass
                if all_dead and empty:return 'ACKNOWLEDGED_CLEANUP'
                reason='WATCHDOG_PREMATURE_STOP';break
            reason='WATCHDOG_REVOKED' if value==b'R' else 'WATCHDOG_CHANNEL_LOST'
            break
    failures=[]
    try:
        os.lseek(cgroup_kill_fd,0,os.SEEK_SET)
        if os.write(cgroup_kill_fd,b'1')!=1: raise OSError('short cgroup kill')
    except OSError as exc: failures.append(exc)
    for fd in process_pidfds:
        try: signal.pidfd_send_signal(fd,signal.SIGKILL)
        except ProcessLookupError: pass
        except OSError as exc: failures.append(exc)
    try:
        os.write(partial_marker_fd,(reason+'\n').encode('ascii')); os.fsync(partial_marker_fd)
    except OSError as exc: failures.append(exc)
    if failures: raise ExceptionGroup('watchdog cleanup requires operator review',failures)
    return reason
