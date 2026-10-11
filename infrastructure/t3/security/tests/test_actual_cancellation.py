"""Actual local processes/SQLite cancellation; NOT cgroup/GitHub/UID isolation proof."""
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.security.process import ProcessRecord
from infrastructure.t3.security.ledger import Ledger
from infrastructure.t3.security.protocol import sign
from infrastructure.t3.security.watchdog import EnrolledJobWatchdog


def record(child):
    with open(f'/proc/{child.pid}/stat') as f: stat=f.read()
    with open(f'/proc/{child.pid}/cgroup') as f: cgroup=f.read().strip()
    with open(f'/proc/{child.pid}/exe','rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
    return ProcessRecord(child.pid,os.pidfd_open(child.pid),os.getuid(),int(stat[stat.rfind(')')+2:].split()[19]),cgroup,digest)


def test_cancel_ends_real_lease_kills_retained_children_preserves_partial():
    children=[subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']) for _ in range(2)]
    records=[]
    try:
        records=[record(c) for c in children]
        for r in records:r.verify()
        with tempfile.TemporaryDirectory() as folder:
            now=int(time.time());key=Ed25519PrivateKey.generate()
            ledger=Ledger(folder+'/permits.sqlite',{'owner':key.public_key()},lambda _:None)
            p=dict(version=4,permit_id='local-nonresearch',authority_sha256='a'*64,role='LIFE',subject='nonresearch',attempt=1,issued_at=now,not_before=now,expires_at=now+90,execution_deadline=now+120)
            ledger.issue(sign(p,key,'owner','ADAMON-P4V3-PERMIT'))
            ledger.consume(p['permit_id'],dict(authority_sha256=p['authority_sha256'],role=p['role'],subject=p['subject']),'local-session')
            supervisor=SimpleNamespace(_worker=lambda:records[0])
            def kill_known_children():
                for r in records:r.kill()
            def preserve(reason):
                with open(folder+'/partial.txt','x') as f:f.write(reason)
            watchdog=EnrolledJobWatchdog(supervisor=supervisor,launcher=records[1],ledger=ledger,permit_id=p['permit_id'],session='local-session',kill_cgroup=kill_known_children,preserve_partial=preserve,deadline=time.monotonic()+10)
            watchdog.cancel()
            assert watchdog.run()=='JOB_CANCELLED'
            assert not ledger.session_live(p['permit_id'],'local-session')
            for c in children:assert c.wait(timeout=5)==-9
            with open(folder+'/partial.txt') as f:assert f.read()=='JOB_CANCELLED'
            ledger.verify_chain()
    finally:
        for c in children:
            if c.poll() is None:c.kill()
            c.wait()
        for r in records:os.close(r.pidfd)
