"""Real C# inherited-FD transport -> Python validator. NOT full Runner/GitHub proof."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid
import pytest
from infrastructure.t3.security.process import ProcessRecord
from infrastructure.t3.security.protocol import Denied
from infrastructure.t3.security.supervisor import Supervisor
from infrastructure.t3.runner.assignment import decode_assignment


def record(pid, pidfd):
    base=Path('/proc')/str(pid)
    stat=(base/'stat').read_text()
    return ProcessRecord(pid,pidfd,int(next(s for s in (base/'status').read_text().splitlines() if s.startswith('Uid:')).split()[1]),
        int(stat[stat.rfind(')')+2:].split()[19]),(base/'cgroup').read_text().strip(),
        hashlib.sha256((base/'exe').read_bytes()).hexdigest())


def test_actual_csharp_assignment_stream_rejected_before_worker_factory():
    dotnet=Path('/workspace/.cache/adamon-dotnet/dotnet')
    dll=Path('/workspace/.cache/t3-runner-transport/TransportHarness.dll')
    if not dotnet.is_file() or not dll.is_file():pytest.skip('explicit C# transport build unavailable')
    parent,child=socket.socketpair()
    pipes=[]
    for _ in range(2):
        rd,wr=os.pipe();os.close(wr);pipes.append(rd)
    from infrastructure.t3.runner.tests.test_assignment import packet
    candidate=packet()
    candidate['steps'][0]['inputs']['map'][0]['value']='echo unauthorized'
    raw=json.dumps(candidate)
    request={'version':1,'operation':'listener_snapshot_spawn','request_id':str(uuid.uuid4()),
        'payload':{'raw_assignment':raw,'assignment_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
    process=subprocess.Popen([str(dotnet),str(dll),str(child.fileno()),json.dumps(request),*map(str,pipes)],
        pass_fds=(child.fileno(),*pipes),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    child.close();pidfd=os.pidfd_open(process.pid)
    called=[]
    def factory(*_):
        called.append(True)
        raise AssertionError('unauthorized assignment reached native worker spawn')
    def validate(packet):
        wire=json.dumps(packet)
        try:return decode_assignment(wire,hashlib.sha256(wire.encode()).hexdigest())
        except ValueError as exc:raise Denied('pinned assignment refused') from exc
    supervisor=Supervisor(record(process.pid,pidfd),factory,validate,None,{},lambda *_:None)
    try:
        supervisor.serve_private(parent,'LISTENER')
        out,err=process.communicate(timeout=5)
        assert process.returncode!=0
        assert 'P4_SUPERVISOR_DENIED' in err
        assert called==[] and supervisor.dispatch is None
    finally:
        parent.close()
        if process.poll() is None:process.kill();process.wait()
        for fd in pipes+[pidfd]:os.close(fd)
