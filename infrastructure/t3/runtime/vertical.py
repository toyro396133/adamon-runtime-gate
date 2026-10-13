"""Closed nonresearch vertical canary; never a research execution entry.

Joins retained Supervisor assignment, authoritative permit ledger, locally owned
process birth, sealed FD key transfer, signed injection/completion and cleanup.
This is a process canary, NOT Runner deployment, mTLS enrollment or microVM proof.
The only subject and adapter are compiled into this module; no command/path/RPC
parameter can select research code. REST provenance is supplied by Supervisor.
"""
import array
import hashlib
import multiprocessing
import os
import select
import signal
import socket
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..security.process import ProcessRecord
from ..security.session import assignment_binding
from ..security.protocol import Denied, canonical, digest, sign
from .guest import BINDING, GuestClient, receive, send
from .injection import VerifiedGuestDispatch, issue

SUBJECT='NONRESEARCH_SOCKET_CANARY'
SOURCE=b'ADAMON closed nonresearch byte digest adapter v1'
FIXTURE=b'nonresearch fixed input v1'
RECEIPT_DOMAIN='ADAMON-NONRESEARCH-VERTICAL-RECEIPT'


def owned_record(pid):
    """Called only immediately after this controller's own child birth."""
    fd=os.pidfd_open(pid)
    try:
        base=Path('/proc')/str(pid)
        raw=(base/'stat').read_text()
        uid=int(next(s for s in (base/'status').read_text().splitlines() if s.startswith('Uid:')).split()[1])
        record=ProcessRecord(pid,fd,uid,int(raw[raw.rfind(')')+2:].split()[19]),
            (base/'cgroup').read_text().strip(),hashlib.sha256((base/'exe').read_bytes()).hexdigest())
        record.verify()
        return record
    except BaseException:
        os.close(fd)
        raise


def _guest(path, binding, owner_public, close_fd):
    # Inherited server descriptor is not retained by the child.
    if close_fd is not None:os.close(close_fd)
    stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    stream.settimeout(5)
    stream.connect(path)
    fds=[]
    try:
        body,ancillary,flags,_=stream.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
        for level,kind,data in ancillary:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise Denied('canary key ancillary')
            values=array.array('i');values.frombytes(data[:len(data)-len(data)%values.itemsize]);fds.extend(values)
        if body!=b'K' or flags&socket.MSG_CTRUNC or len(fds)!=1:raise Denied('canary key frame')
        import fcntl
        if os.fstat(fds[0]).st_size!=32 or fcntl.fcntl(fds[0],1034)&15!=15:raise Denied('canary key not sealed')
        key=Ed25519PrivateKey.from_private_bytes(os.pread(fds[0],32,0))
        os.close(fds.pop())
        artifact=None
        def adapter(source,fixture):
            nonlocal artifact
            database=sqlite3.connect(':memory:')
            try:
                database.execute('CREATE TABLE canary(value TEXT)')
                database.execute('INSERT INTO canary VALUES(?)',('nonresearch',))
                database.commit();artifact=database.serialize()
            finally:database.close()
            payload=artifact
            return [dict(object_id=hashlib.sha256(b'canary-object').hexdigest(),version_id='nonresearch-v1',
                sha256=hashlib.sha256(payload).hexdigest(),size_bytes=len(payload))]
        VerifiedGuestDispatch(binding,owner_public,key,SOURCE,FIXTURE,
            {('LIFE',SUBJECT):adapter}).serve(stream)
        # Keep owned process live until parent verifies signed completion and
        # requests successful cleanup. EOF/crash cannot masquerade as success.
        if receive(stream)!={'version':4,'operation':'nonresearch-export'} or artifact is None:
            raise Denied('canary export protocol')
        send(stream,{'version':4,'artifact_hex':artifact.hex()})
        if receive(stream)!={'version':4,'operation':'nonresearch-cleanup'}:raise Denied('canary cleanup protocol')
    finally:
        for fd in fds:os.close(fd)
        stream.close()


class NonresearchVerticalController:
    def __init__(self, *, supervisor, ledger, permit_id, binding, owner_key,
                 receipt_key, preserve_partial):
        self.supervisor=supervisor;self.ledger=ledger;self.permit_id=permit_id
        self.binding=dict(binding);self.owner=owner_key;self.receipt_key=receipt_key
        self.preserve_partial=preserve_partial;self.used=False
        self.record=None;self.child=None;self.phase='CONSTRUCTED';self.artifact=None
        if self.binding.get('subject')!=SUBJECT or self.binding.get('role')!='LIFE':
            raise Denied('nonresearch closed subject')
        if not callable(preserve_partial):raise Denied('retained partial sink required')

    def _live(self):
        d=self.supervisor.dispatch
        if d is None or d.revoked or not d.acknowledged or not d.authorized:
            raise Denied('authorized retained assignment absent')
        d.worker.verify();self.supervisor.correlate(d.assignment)
        expected=assignment_binding(d.assignment,d.sha256)
        for key,value in expected.items():
            if key not in self.binding or canonical(value)!=canonical(self.binding[key]):
                raise Denied('vertical assignment binding: '+key)
        return d

    def _receipt(self,status,reason):
        payload=dict(version=2,artifact_sha256=None if self.artifact is None else hashlib.sha256(self.artifact).hexdigest(),
            artifact_size=None if self.artifact is None else len(self.artifact),scope='NONRESEARCH_LOCAL_PROCESS_CANARY',status=status,
            phase=self.phase,reason=reason,permit_id=self.permit_id,binding_sha256=digest(self.binding))
        return sign(payload,self.receipt_key,'nonresearch-receipt',RECEIPT_DOMAIN)

    def run(self, *, cancelled=lambda:False, deadline_seconds=5):
        if self.used or type(deadline_seconds) not in (int,float) or not 0<deadline_seconds<=10:
            raise Denied('nonresearch one-shot/deadline')
        self.used=True;session=str(uuid.uuid4());stream=None;key_fd=None
        try:
            self.phase='ASSIGNMENT';self._live()
            self.phase='PERMIT';permit=self.ledger.consume(self.permit_id,self.binding,session)
            if permit['subject']!=SUBJECT or permit['role']!='LIFE':raise Denied('nonresearch permit subject')
            guest_binding={k:self.binding[k] for k in BINDING-{'permit_sha256'}}
            guest_binding['permit_sha256']=digest(permit)
            if guest_binding['source_sha256']!=hashlib.sha256(SOURCE).hexdigest() or guest_binding['fixture_sha256']!=hashlib.sha256(FIXTURE).hexdigest():
                raise Denied('nonresearch fixed source/fixture')
            self.phase='BIRTH'
            with tempfile.TemporaryDirectory(prefix='adamon-nonresearch-') as directory:
                path=directory+'/guest.sock'
                server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    server.bind(path);os.chmod(path,0o600);server.listen(1);server.settimeout(5)
                    guest_key=Ed25519PrivateKey.generate()
                    self.child=multiprocessing.get_context('spawn').Process(target=_guest,
                        args=(path,guest_binding,self.owner.public_key().public_bytes_raw(),None))
                    self.child.start();self.record=owned_record(self.child.pid)
                    stream,_=server.accept();self.record.authenticate(stream)
                finally:server.close()
                self.phase='BOOTSTRAP'
                import fcntl
                key_fd=os.memfd_create('nonresearch-guest-key',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
                os.write(key_fd,guest_key.private_bytes_raw());fcntl.fcntl(key_fd,1033,15)
                stream.sendmsg([b'K'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[key_fd]))])
                os.close(key_fd);key_fd=None
                self.phase='INJECTION';self._live();self.record.verify()
                client=GuestClient(stream,guest_binding,guest_key.public_key().public_bytes_raw())
                envelope=issue(guest_binding,SOURCE,FIXTURE,guest_key.public_key().public_bytes_raw(),
                    int(time.time())+60,self.owner)
                client.execute(envelope)
                self.phase='EXECUTING';deadline=time.monotonic()+deadline_seconds
                result=None
                while result is None:
                    if cancelled():raise Denied('nonresearch cancelled')
                    if time.monotonic()>=deadline:raise Denied('nonresearch deadline')
                    self._live();self.record.verify()
                    if not self.ledger.session_live(self.permit_id,session):raise Denied('permit lease lost')
                    result=client.poll_completion(.02)
                self._live()
                send(stream,{'version':4,'operation':'nonresearch-export'})
                stream.settimeout(max(.001,deadline-time.monotonic()))
                exported=receive(stream)
                if cancelled() or time.monotonic()>=deadline:raise Denied('nonresearch export cancelled/deadline')
                self._live();self.record.verify()
                if not self.ledger.session_live(self.permit_id,session):raise Denied('permit lease lost')
                if type(exported) is not dict or set(exported)!={'version','artifact_hex'} or exported['version']!=4:
                    raise Denied('canary export schema')
                try:artifact=bytes.fromhex(exported['artifact_hex'])
                except (ValueError,TypeError):raise Denied('canary artifact encoding')
                refs=result['artifacts']
                if len(refs)!=1 or refs[0]['sha256']!=hashlib.sha256(artifact).hexdigest() or refs[0]['size_bytes']!=len(artifact):
                    raise Denied('canary signed artifact mismatch')
                self.artifact=artifact
                send(stream,{'version':4,'operation':'nonresearch-cleanup'})
                self.child.join(2)
                if self.child.exitcode!=0:raise Denied('nonresearch guest cleanup failed')
                self.phase='COMPLETE';self.ledger.end_session(self.permit_id,session,'NONRESEARCH_COMPLETE')
                return dict(completion=result,artifact_bytes=self.artifact,receipt=self._receipt('COMPLETE','owned guest exited'))
        except BaseException as failure:
            errors=[]
            if self.record is not None:
                try:self.record.kill()
                except ProcessLookupError:pass
                except BaseException as exc:errors.append(exc)
            if self.child is not None:
                try:
                    # A capture failure must not leak the just-created child.
                    # multiprocessing retains this unreaped owned birth handle.
                    if self.record is None and self.child.is_alive():self.child.kill()
                    self.child.join(2)
                    if self.child.is_alive():raise Denied('owned guest survived cleanup')
                except BaseException as exc:errors.append(exc)
            for action in (lambda:self.ledger.end_session(self.permit_id,session,'NONRESEARCH_PARTIAL'),
                           lambda:self.preserve_partial(self._receipt('PARTIAL',type(failure).__name__))):
                try:action()
                except BaseException as exc:errors.append(exc)
            if errors:raise ExceptionGroup('nonresearch cleanup failed',[failure,*errors])
            raise
        finally:
            if stream is not None:stream.close()
            if key_fd is not None:os.close(key_fd)
            if self.record is not None:os.close(self.record.pidfd)
