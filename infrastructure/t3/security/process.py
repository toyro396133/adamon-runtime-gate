"""Supervisor-owned process references. Never enroll a PID supplied by a step."""
import hashlib
import os
import select
import signal
import socket
import struct
from dataclasses import dataclass
from .protocol import Denied

@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    pidfd: int
    uid: int
    start_ticks: int
    cgroup: str
    executable_sha256: str

    def verify(self):
        poll=select.poll(); poll.register(self.pidfd,select.POLLIN)
        if poll.poll(0): raise Denied('process exited')
        base=f'/proc/{self.pid}'
        with open(base+'/stat') as f: stat=f.read()
        start=int(stat[stat.rfind(')')+2:].split()[19])
        with open(base+'/status') as f: status=f.read().splitlines()
        uid_line=next(x for x in status if x.startswith('Uid:'))
        if any(int(x)!=self.uid for x in uid_line.split()[1:]): raise Denied('UID changed')
        with open(base+'/cgroup') as f: cg=f.read().strip()
        with open(base+'/exe','rb') as exe:
            sha=hashlib.file_digest(exe,'sha256').hexdigest()
        if start!=self.start_ticks or cg!=self.cgroup or sha!=self.executable_sha256:
            raise Denied('process identity changed')
    def authenticate(self, connected_socket):
        self.verify()
        pid,uid,_=struct.unpack('3i',connected_socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if pid!=self.pid or uid!=self.uid: raise Denied('peer is not registered launcher')
        self.verify()
    def kill(self):
        signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)

def kill_job_cgroup(directory):
    """Directory must be supervisor-opened and retained, never caller-supplied path."""
    fd=os.open('cgroup.kill',os.O_WRONLY|os.O_NOFOLLOW,dir_fd=directory)
    try: os.write(fd,b'1')
    finally: os.close(fd)

def spawn_verified_launcher(*args, **kwargs):
    """No fork/PID fallback to the unimplemented clone3+LSM isolated spawn."""
    raise Denied('BLOCKED: clone3/execveat immutable image, UID/namespace/seccomp/LSM preflight not implemented')
