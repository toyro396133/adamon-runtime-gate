"""Private-FD supervisor state machine; candidate only, no execution freeze.

All injected services are owner-created capabilities, not workflow parameters.
The current research start is unconditional BLOCKED. This implements assignment,
Worker acknowledgement, REST correlation and credential preparation so a future
independently reviewed deployment need not invent an enrollment mechanism.
"""
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from .protocol import Denied, canonical, spki_digest
from .process import ProcessRecord

MARKER='ADAMON_P4_FIXED_LAUNCH_V4'

def exact(a,b):
    return canonical(a)==canonical(b)

@dataclass
class Dispatch:
    raw: str
    sha256: str
    assignment: dict
    worker: ProcessRecord
    acknowledged: bool=False
    authorized: bool=False
    revoked: bool=False

class Supervisor:
    def __init__(self, listener, worker_factory, assignment_validator,
                 rest_client, approved_identity, cleanup):
        if not isinstance(listener,ProcessRecord): raise Denied('owner-created Listener record required')
        self.listener=listener
        self.spawn_worker=worker_factory
        self.validate_assignment=assignment_validator
        self.rest=rest_client
        self.expected=dict(approved_identity)
        self.cleanup=cleanup
        self.lock=threading.RLock()
        self.dispatch=None
        self.request_ids=set()
        self._private_context=threading.local()

    def serve_private(self, sock, role):
        # socketpair credentials identify its creator, NOT the child. Identity
        # here derives from owner-created retained endpoint and birth pidfd.
        from .bridge import handle
        record=self.listener if role=='LISTENER' else self._worker()
        record.verify()
        self._private_context.role=role
        try: return handle(sock,role,self)
        finally: self._private_context.role=None

    def _worker(self):
        if self.dispatch is None or self.dispatch.revoked: raise Denied('no live dispatch')
        return self.dispatch.worker

    def handle_private_message(self,role,message,fds):
        with self.lock:
            if role!=getattr(self._private_context,'role',None): raise Denied('private retained channel required')
            request_id=message['request_id']
            if request_id in self.request_ids: raise Denied('bridge replay')
            self.request_ids.add(request_id)
            op=message['operation']; p=message['payload']
            (self.listener if role=='LISTENER' else self._worker()).verify()
            if op=='revoke':
                self.revoke(p['reason']); return 0
            if op=='listener_snapshot_spawn':
                if role!='LISTENER' or self.dispatch is not None or len(fds)!=2: raise Denied('dispatch uniqueness')
                raw=p['raw_assignment']
                if hashlib.sha256(raw.encode()).hexdigest()!=p['assignment_sha256']: raise Denied('raw digest')
                def unique(pairs):
                    out={}
                    for k,v in pairs:
                        if k in out: raise Denied('assignment duplicate')
                        out[k]=v
                    return out
                assignment=json.loads(raw,object_pairs_hook=unique)
                # Pinned schema/closed step policy injected from private authority.
                normalized=self.validate_assignment(assignment)
                canonical(normalized)
                worker=self.spawn_worker(os.dup(fds[0]),os.dup(fds[1]),raw)
                if not isinstance(worker,ProcessRecord): raise Denied('birth-created Worker record required')
                worker.verify()
                self.dispatch=Dispatch(raw,p['assignment_sha256'],normalized,worker)
                return WorkerCompletion(worker,self.revoke)
            d=self.dispatch
            if d is None or d.revoked or not exact(p.get('assignment_sha256'),d.sha256): raise Denied('assignment mismatch')
            if op=='worker_ack':
                if d.acknowledged or p['raw_assignment']!=d.raw: raise Denied('Worker raw snapshot mismatch/replay')
                d.acknowledged=True; return 0
            if not d.acknowledged: raise Denied('Worker acknowledgement required')
            if p['step_id']!=d.assignment['step_id'] or d.assignment['marker']!=MARKER: raise Denied('fixed step mismatch')
            if op=='authorize_assignment':
                self.correlate(d.assignment)
                if d.authorized: raise Denied('authorization replay')
                d.authorized=True; return 0
            if op=='fixed_step_execute':
                if not d.authorized: raise Denied('authorization absent')
                self.correlate(d.assignment)
                # Deliberately cannot launch research in this implementation stage.
                raise Denied('NO_APPROVED_EXECUTION_FREEZE')
            raise Denied('unknown operation')

    def correlate(self,a):
        run=self.rest.get_run(a['run_id'],a['run_attempt'])
        for key in ('workflow_ref','workflow_sha','ref','head_sha','run_id','run_attempt','repository'):
            if key not in self.expected or not exact(a.get(key),self.expected[key]) or not exact(run.get(key),self.expected[key]):
                raise Denied('workflow/ref/SHA/run correlation')
        jobs=self.rest.list_jobs(a['run_id'],a['run_attempt'])
        active=[j for j in jobs if j.get('status')=='in_progress']
        if len(active)!=1: raise Denied('ambiguous active Job')
        job=active[0]
        for key in ('job_id','run_id','run_attempt','runner_id'):
            if type(a.get(key)) is not int or a[key]<=0 or not exact(job.get(key),a[key]): raise Denied('REST numeric Job binding')
        if not exact(a.get('runner_id'),self.expected.get('runner_id')): raise Denied('runner mismatch')
        return job

    def revoke(self,reason):
        with self.lock:
            if self.dispatch and not self.dispatch.revoked:
                self.dispatch.revoked=True
                self.cleanup(reason,self.dispatch.worker)

class WorkerCompletion:
    """Listener response waits for actual Worker exit outside supervisor lock."""
    def __init__(self,worker,revoke): self.worker,self.revoke=worker,revoke
    def wait(self):
        import select
        poll=select.poll();poll.register(self.worker.pidfd,select.POLLIN)
        poll.poll()  # Independent Worker bridge/cancel handler remains available.
        info=os.waitid(os.P_PIDFD,self.worker.pidfd,os.WEXITED|os.WNOWAIT)
        self.revoke('worker_exit')
        if info.si_code!=os.CLD_EXITED: return 1
        return info.si_status

class BootstrapCA:
    """Issue only after a supervisor-owned live launcher record is rechecked.

    This is key/certificate construction, not authorization to start research.
    Caller must transfer key FD only through the retained launcher bootstrap FD.
    """
    def __init__(self,ca_cert,ca_key,native,binding_oid):
        self.cert,self.key,self.native,self.oid=ca_cert,ca_key,native,binding_oid
    def issue(self,record,binding):
        if not isinstance(record,ProcessRecord): raise Denied('launcher birth record')
        record.verify(); encoded=canonical(binding)
        key=Ed25519PrivateKey.generate()
        spki=spki_digest(key.public_key())
        now=datetime.now(timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'p4-private-launcher')]))
              .issuer_name(self.cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(seconds=30)).not_valid_after(now+timedelta(seconds=60))
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
              .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
              .add_extension(x509.UnrecognizedExtension(self.oid,encoded),critical=True).sign(self.key,None))
        record.verify()
        raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        fd=self.native.sealed_key(raw)
        del raw,key
        try: record.verify()
        except BaseException: os.close(fd); raise
        return fd,cert,spki
