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
            # Defense in depth: the bridge rejects role confusion too, but the
            # privileged state machine must never trust that it was its caller.
            if ((op=='listener_snapshot_spawn' and role!='LISTENER') or
                (op in {'worker_ack','authorize_assignment','fixed_step_execute'}
                 and role!='WORKER')):
                raise Denied('private endpoint operation/role mismatch')
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
                normalized=(self.validate_assignment.from_raw(raw,p['assignment_sha256'])
                            if isinstance(self.validate_assignment,RunnerAssignmentBinder)
                            else self.validate_assignment(assignment))
                canonical(normalized)
                worker=self.spawn_worker(os.dup(fds[0]),os.dup(fds[1]),raw)
                if not isinstance(worker,ProcessRecord): raise Denied('birth-created Worker record required')
                worker.verify()
                self.dispatch=Dispatch(raw,p['assignment_sha256'],normalized,worker)
                if isinstance(self.spawn_worker,NativeWorkerSpawner): self.spawn_worker.start(self,worker)
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
        for key in ('workflow_ref','workflow_sha','ref','head_sha','run_id','run_attempt','repository','repository_id'):
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

class RunnerAssignmentBinder:
    """Pinned raw Runner decoder + independently authenticated REST Job mapping.

    Orchestration Job GUID and Check Run ID are NOT REST Actions Job IDs.
    Trusted owner configuration supplies runner_id, never Workflow context.
    """
    def __init__(self, decoder, rest, *, runner_id):
        if not callable(decoder) or type(runner_id) is not int or runner_id<=0:
            raise Denied('trusted decoder/registered Runner identity required')
        self.decoder,self.rest,self.runner_id=decoder,rest,runner_id
    def from_raw(self, raw, sha256):
        return self._bind(self.decoder(raw,sha256))
    def __call__(self, raw):
        return self._bind(self.decoder(raw))
    def _bind(self, decoded):
        a=dict(decoded)
        check=a.get('check_run_id')
        if type(check) is not int or not 0<check<=2**53-1:
            raise Denied('numeric assignment Check Run ID required')
        jobs=self.rest.list_jobs(a['run_id'],a['run_attempt'])
        matched=[j for j in jobs if j.get('check_run_id')==check and j.get('runner_id')==self.runner_id and j.get('status')=='in_progress']
        if len(matched)!=1: raise Denied('unique REST Check/Job/Runner binding absent')
        a['job_id']=matched[0]['job_id'];a['runner_id']=self.runner_id
        return a

class NativeWorkerSpawner:
    """Retain a new private Worker endpoint; inherited FD199 is the only channel.

    Native factory owns fixed executable/UID/cgroup. Listener's authenticated
    bridge supplies only two pipe FDs, never executable or process identity.
    """
    def __init__(self, factory):
        from .native import NativeProcessFactory
        if not isinstance(factory,NativeProcessFactory):raise Denied('native birth factory required')
        self.factory=factory;self.pending={};self.threads=[]
    def __call__(self, channel_in, channel_out, raw):
        import socket
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            record=self.factory.spawn('WORKER',child.fileno(),channel_in=channel_in,channel_out=channel_out)
            self.pending[record.pidfd]=parent
            return record
        except BaseException:
            parent.close();raise
        finally:
            child.close();os.close(channel_in);os.close(channel_out)
    def start(self, supervisor, record):
        channel=self.pending.pop(record.pidfd)
        def serve():
            try:
                while supervisor.dispatch is not None and not supervisor.dispatch.revoked:
                    supervisor.serve_private(channel,'WORKER')
            except BaseException:supervisor.revoke('WORKER_BRIDGE_FAILED')
            finally:channel.close()
        thread=threading.Thread(target=serve,name='p4-retained-worker',daemon=True)
        self.threads.append(thread);thread.start()

def deliver_launcher_bootstrap(ca, record, binding, connected_socket):
    """Transfer one sealed key only to accepted live Launcher peer, never Workflow.

    Connected socket must come from supervisor-owned AF_UNIX accept(), not a
    pre-fork socketpair (SO_PEERCRED would identify its creator). No permit is
    consumed here: mTLS/channel challenge and complete binding remain mandatory.
    """
    import array, socket, struct
    record.authenticate(connected_socket)
    fd,cert,spki=ca.issue(record,binding)
    try:
        record.authenticate(connected_socket)
        from cryptography.hazmat.primitives import serialization
        payload=canonical(dict(version=4,spki_sha256=spki,binding=binding,
                         certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode('ascii')))
        header=struct.pack('!I',len(payload))
        sent=connected_socket.sendmsg([header+payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        if sent<=0:raise Denied('bootstrap transfer failed')
        if sent<len(header)+len(payload):connected_socket.sendall((header+payload)[sent:])
        record.verify()
        return spki
    finally:os.close(fd)

def connect_native_supervisor(*, listener, native_factory, repository,
                              owner_token_provider, approved_identity, cleanup):
    """Closed composition of the concrete Runner decoder, REST and native bridge.

    Owner installs/provisions the retained Listener and immutable image first.
    No workflow API can supply paths, argv, PIDs, approved identities or tokens.
    """
    from .native import NativeProcessFactory
    from .github_rest import GitHubApi,OwnerAuthenticatedTransport
    from ..runner.assignment import decode_assignment
    if not isinstance(native_factory,NativeProcessFactory):raise Denied('native factory required')
    if approved_identity.get('repository')!=repository:raise Denied('owner repository mismatch')
    rest=GitHubApi(repository,get_json=OwnerAuthenticatedTransport(token_provider=owner_token_provider))
    binder=RunnerAssignmentBinder(decode_assignment,rest,runner_id=approved_identity['runner_id'])
    spawner=NativeWorkerSpawner(native_factory)
    return Supervisor(listener,spawner,binder,rest,approved_identity,cleanup)
