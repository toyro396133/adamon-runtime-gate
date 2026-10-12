"""Fixed nonresearch Guest init and deferred Launcher guest driver.

The only compiled adapter makes a small SQLite canary in memory. There is no
scientific import, dynamic module, uploaded program, path or command dispatch.
The rootfs owner key is an immutable build input, never supplied by a Workflow.
"""
import hashlib
import os
import socket
import sqlite3
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..runtime.guest import GuestClient, receive, send, validate_binding
from ..runtime.injection import VerifiedGuestDispatch,issue
from ..runtime.launcher import LocalLauncher
from ..runtime.microvm import Blocked

SUBJECT='NONRESEARCH_SOCKET_CANARY'
SOURCE=b'ADAMON closed nonresearch byte digest adapter v1'
FIXTURE=b'nonresearch fixed input v1'


def closed_binding(binding):
    validate_binding(binding)
    if binding['role']!='LIFE' or binding['subject']!=SUBJECT or binding['source_sha256']!=hashlib.sha256(SOURCE).hexdigest() or binding['fixture_sha256']!=hashlib.sha256(FIXTURE).hexdigest():
        raise Blocked('NONRESEARCH_IMAGE_SUBJECT_ONLY')


def artifact_bytes():
    db=sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE canary(value TEXT NOT NULL)')
        db.execute("INSERT INTO canary VALUES ('nonresearch')")
        db.commit();return db.serialize()
    finally:db.close()


def serve_nonresearch_image(stream,owner_public_key,clock=time.time):
    """Actual Guest server transport; AF_VSOCK init and AF_UNIX local test share it."""
    if type(owner_public_key) is not bytes or len(owner_public_key)!=32:
        raise Blocked('NONRESEARCH_IMAGE_OWNER_KEY')
    stream.settimeout(30)
    key=Ed25519PrivateKey.generate()
    send(stream,{'version':1,'operation':'nonresearch-guest-ready',
                 'completion_public_key_hex':key.public_key().public_bytes_raw().hex()})
    boot=receive(stream)
    if type(boot) is not dict or set(boot)!={'version','operation','binding','delegation'} or type(boot['version']) is not int or boot['version']!=1 or boot['operation']!='nonresearch-boot':
        raise Blocked('NONRESEARCH_IMAGE_BOOT')
    binding=boot['binding'];closed_binding(binding)
    from .delegation import verify_delegation
    delegated_public,expires_at=verify_delegation(boot['delegation'],owner_public_key,binding,clock)
    produced=[]
    def canary(source,fixture):
        # Dispatch verifies original source/fixture against owner signature first.
        if not clock()<expires_at:raise Blocked('CANARY_DELEGATION_EXPIRY')
        if source!=SOURCE or fixture!=FIXTURE:raise Blocked('NONRESEARCH_SOURCE_PIN')
        value=artifact_bytes();produced.append(value)
        digest=hashlib.sha256(value).hexdigest()
        return [{'object_id':digest,'version_id':'nonresearch-guest-init-v1',
                 'sha256':digest,'size_bytes':len(value)}]
    VerifiedGuestDispatch(binding,delegated_public,key,SOURCE,FIXTURE,
                         {('LIFE',SUBJECT):canary},clock).serve(stream)
    command=receive(stream)
    if command!={'version':1,'operation':'nonresearch-export'} or len(produced)!=1:
        raise Blocked('NONRESEARCH_IMAGE_EXPORT')
    send(stream,{'version':1,'operation':'nonresearch-artifact',
                 'artifact_hex':produced[0].hex()})
    if receive(stream)!={'version':1,'operation':'nonresearch-cleanup'}:
        raise Blocked('NONRESEARCH_IMAGE_CLEANUP')
    return 'NONRESEARCH_COMPLETE'


class NonresearchBootGuest:
    """Connects only after InstanceStart; signs the ephemeral guest key binding."""
    def __init__(self,launcher,binding,delegate_signer,delegation,owner_public_key,clock=time.time):
        if not isinstance(launcher,LocalLauncher):raise Blocked('LOCAL_OWNER_LAUNCHER_REQUIRED')
        closed_binding(binding)
        from ..runtime.guest import canonical
        self._binding=canonical(binding);self.launcher=launcher
        from .delegation import verify_delegation
        public,expiry=verify_delegation(delegation,owner_public_key,binding,clock)
        if delegate_signer.public_key().public_bytes_raw()!=public:raise Blocked('CANARY_DELEGATION_SIGNER_MISMATCH')
        if public==owner_public_key:raise Blocked('OWNER_ROOT_KEY_NOT_DELEGATE')
        self.signer=delegate_signer;self.delegation=canonical(delegation)
        self.owner_public_key=owner_public_key;self.clock=clock;self.client=None;self.used=False
        self.artifact=None;self.completion=None
    @property
    def binding(self):
        import json
        return json.loads(self._binding)
    def execute(self,_launch_attestation=None,timeout=30):
        if self.used:raise Blocked('NONRESEARCH_IMAGE_ONE_SHOT')
        from .delegation import verify_delegation
        import json
        delegation=json.loads(self.delegation)
        _,expiry=verify_delegation(delegation,self.owner_public_key,self.binding,self.clock)
        self.used=True;stream=self.launcher.guest()
        try:
            ready=receive(stream)
            if type(ready) is not dict or set(ready)!={'version','operation','completion_public_key_hex'} or type(ready['version']) is not int or ready['version']!=1 or ready['operation']!='nonresearch-guest-ready':
                raise Blocked('NONRESEARCH_IMAGE_READY')
            public=bytes.fromhex(ready['completion_public_key_hex'])
            if len(public)!=32:raise Blocked('NONRESEARCH_IMAGE_COMPLETION_KEY')
            send(stream,{'version':1,'operation':'nonresearch-boot','binding':self.binding,'delegation':delegation})
            envelope=issue(self.binding,SOURCE,FIXTURE,public,min(int(self.clock())+60,expiry),self.signer)
            self.client=GuestClient(stream,self.binding,public)
            self.client.execute(envelope,timeout)
        except BaseException:stream.close();self.client=None;raise
    def poll_completion(self,timeout=.1):
        if self.client is None:raise Blocked('NONRESEARCH_IMAGE_NOT_STARTED')
        completion=self.client.poll_completion(timeout)
        if completion is None:return None
        send(self.client.stream,{'version':1,'operation':'nonresearch-export'})
        value=receive(self.client.stream)
        if type(value) is not dict or set(value)!={'version','operation','artifact_hex'} or value['version']!=1 or value['operation']!='nonresearch-artifact':
            raise Blocked('NONRESEARCH_IMAGE_ARTIFACT')
        body=bytes.fromhex(value['artifact_hex'])
        expected=completion['artifacts']
        if len(expected)!=1 or len(body)!=expected[0]['size_bytes'] or hashlib.sha256(body).hexdigest()!=expected[0]['sha256']:
            raise Blocked('NONRESEARCH_IMAGE_ARTIFACT_BINDING')
        self.artifact=body;self.completion=completion
        send(self.client.stream,{'version':1,'operation':'nonresearch-cleanup'})
        return completion
    def close(self):
        if self.client is not None:self.client.stream.close();self.client=None


def guest_init():
    """Fixed rootfs entry. The kernel/rootfs/owner key must all be image pinned."""
    fd=os.open('/owner-public-key',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_size!=32:raise Blocked('NONRESEARCH_IMAGE_OWNER_KEY')
        owner_key=os.pread(fd,32,0)
    finally:os.close(fd)
    listener=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
    try:
        listener.bind((socket.VMADDR_CID_ANY,52));listener.listen(1)
        listener.settimeout(300);stream,_=listener.accept()
        try:serve_nonresearch_image(stream,owner_key)
        finally:stream.close()
    finally:listener.close()
    # Fixed PID1 poweroff, never shell/restart/another subject. Actual kernel
    # support remains owner-live verification; failure must panic/fail closed.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.reboot(ctypes.c_int(0x4321fedc))<0:
        raise OSError(ctypes.get_errno(),'fixed nonresearch guest poweroff')
    return 'NONRESEARCH_COMPLETE'


if __name__=='__main__':guest_init()
