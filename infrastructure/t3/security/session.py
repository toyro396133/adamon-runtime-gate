"""Real mTLS → one-shot proof → atomic permit consume; no research execution API."""
import struct
import uuid
import select
import time
from dataclasses import dataclass
from .protocol import Denied, Challenges, canonical, decode, digest
from .openssl_channel import accept

MAX_FRAME=1024*1024

def _send(conn,value):
    body=canonical(value)
    if len(body)>MAX_FRAME:raise Denied('session frame limit')
    data=struct.pack('!I',len(body))+body
    offset=0;deadline=time.monotonic()+30
    while offset<len(data):
        offset+=_io(conn,lambda:conn.send(data[offset:]),deadline)

def _io(conn, operation, deadline):
    from OpenSSL import SSL
    while True:
        try:return operation()
        except (SSL.WantReadError,SSL.WantWriteError) as exc:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise Denied('session IO deadline')
            read=[conn] if isinstance(exc,SSL.WantReadError) else []
            write=[conn] if isinstance(exc,SSL.WantWriteError) else []
            r,w,_=select.select(read,write,[],remaining)
            if not r and not w:raise Denied('session IO deadline')

def _read(conn):
    deadline=time.monotonic()+30
    def exact(n):
        data=bytearray()
        while len(data)<n:
            chunk=_io(conn,lambda:conn.recv(n-len(data)),deadline)
            if not chunk:raise Denied('session EOF')
            data.extend(chunk)
        return bytes(data)
    n=struct.unpack('!I',exact(4))[0]
    if not 0<n<=MAX_FRAME:raise Denied('session frame limit')
    return decode(exact(n))

def assignment_binding(assignment, raw_sha256):
    """One closed full-tuple projection shared by session and local canary.

    Input is the Supervisor's retained normalized assignment, never request JSON.
    The raw snapshot digest additionally binds all pinned Worker step fields.
    """
    a=assignment
    workflow_ref=a.get('workflow_ref');repository=a.get('repository');ref=a.get('ref')
    if type(repository) is not str or type(ref) is not str or type(workflow_ref) is not str:
        raise Denied('complete workflow assignment required')
    prefix=repository+'/';suffix='@'+ref
    if not workflow_ref.startswith(prefix) or not workflow_ref.endswith(suffix):
        raise Denied('workflow/repository/ref identity mismatch')
    expected=dict(job_id=a.get('job_id'),run_id=a.get('run_id'),run_attempt=a.get('run_attempt'),
        repository_id=a.get('repository_id'),workflow_path=workflow_ref[len(prefix):-len(suffix)],
        workflow_sha=a.get('workflow_sha'),ref=ref,commit_sha=a.get('head_sha'),
        step_sha256=a.get('step_sha256'),worker_job_guid=a.get('job_guid'),
        worker_request_id=a.get('request_id'),plan_guid=a.get('plan_guid'),assignment_sha256=raw_sha256)
    if any(v is None for v in expected.values()):raise Denied('incomplete assignment identity tuple')
    return expected


@dataclass
class AuthenticatedSession:
    connection: object
    session_id: str
    permit_id: str
    request: dict
    binding: dict
    exporter_sha256: str

class SessionController:
    """All constructor capabilities/binding come from retained owner Supervisor.

    The peer can only prove this exact request, role, assignment and key. It
    cannot select bindings, issue a permit, or authorize Life/Micro computation.
    """
    def __init__(self, *, supervisor, launcher, ledger, permit_id, binding,
                 request, context, ca, oid, expected_spki,
                 kill_job, preserve_partial):
        from .process import ProcessRecord
        if not isinstance(launcher,ProcessRecord):raise Denied('retained launcher required')
        self.supervisor,self.launcher,self.ledger=supervisor,launcher,ledger
        self.permit_id,self.binding,self.request=permit_id,dict(binding),dict(request)
        self.context,self.ca,self.oid,self.spki=context,ca,oid,expected_spki
        self.kill_job,self.preserve_partial=kill_job,preserve_partial
        self.challenges=Challenges()
        if self.binding.get('client_spki_sha256')!=expected_spki or self.binding.get('request_sha256')!=digest(self.request):
            raise Denied('trusted request/key binding required')
    def open(self, raw_socket):
        session=str(uuid.uuid4());conn=None
        try:
            dispatch=self.supervisor.dispatch
            if dispatch is None or dispatch.revoked or not dispatch.acknowledged or not dispatch.authorized:
                raise Denied('verified active assignment required')
            self.supervisor.correlate(dispatch.assignment)
            expected=assignment_binding(dispatch.assignment,dispatch.sha256)
            for key,value in expected.items():
                if key not in self.binding or canonical(self.binding[key])!=canonical(value):
                    raise Denied('permit/assignment identity mismatch: '+key)
            conn,key,exporter=accept(self.context,raw_socket,self.launcher,self.ca,self.oid,canonical(self.binding),self.spki)
            raw_socket.setblocking(False)
            challenge=self.challenges.issue(session,exporter,digest(self.request))
            _send(conn,dict(version=4,challenge=challenge,request=self.request))
            response=_read(conn)
            if type(response) is not dict or set(response)!={'version','proof','signature'} or type(response['version']) is not int or response['version']!=4:
                raise Denied('closed client proof')
            self.challenges.consume(response['proof'],response['signature'],key)
            self.launcher.authenticate(raw_socket)
            self.supervisor.correlate(dispatch.assignment)
            if dispatch.revoked:raise Denied('assignment revoked during handshake')
            self.ledger.consume(self.permit_id,self.binding,session)
            _send(conn,dict(version=4,status='AUTHENTICATED_ONLY',session_id=session))
            return AuthenticatedSession(conn,session,self.permit_id,self.request,self.binding,exporter)
        except BaseException:
            errors=[]
            for action in (lambda:self.ledger.end_session(self.permit_id,session,'SESSION_FAILED'),lambda:self.supervisor.revoke('SESSION_FAILED'),self.kill_job,lambda:self.preserve_partial('SESSION_FAILED')):
                try:action()
                except BaseException as exc:errors.append(exc)
            if conn is not None:
                try:conn.close()
                except Exception:pass
            if errors:raise ExceptionGroup('session rejection cleanup failures',errors)
            raise
