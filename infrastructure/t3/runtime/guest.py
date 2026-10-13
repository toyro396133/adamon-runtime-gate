"""Private same-host vsock stream framing; no shell or guest-selected adapter."""
import hashlib
import json
import socket
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .microvm import Blocked

MAX_FRAME = 1024*1024
DOMAIN = b'ADAMON-P4V4-LOCAL-GUEST-COMPLETION\0'
BINDING = {'job_id', 'run_id', 'run_attempt', 'workflow_sha', 'assignment_sha256',
           'launcher_spki_sha256', 'permit_sha256', 'role', 'subject',
           'source_sha256', 'fixture_sha256'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _read_exact(stream, n):
    out=bytearray()
    while len(out)<n:
        chunk=stream.recv(n-len(out))
        if not chunk: raise Blocked('GUEST_TRUNCATED')
        out.extend(chunk)
    return bytes(out)


def receive(stream):
    size=struct.unpack('!I',_read_exact(stream,4))[0]
    if not 0<size<=MAX_FRAME: raise Blocked('GUEST_FRAME_LIMIT')
    def unique(pairs):
        obj={}
        for k,v in pairs:
            if k in obj: raise Blocked('GUEST_DUPLICATE_KEY')
            obj[k]=v
        return obj
    try: return json.loads(_read_exact(stream,size),object_pairs_hook=unique)
    except (ValueError,UnicodeError): raise Blocked('GUEST_BAD_JSON')


def send(stream, value):
    body=canonical(value)
    if len(body)>MAX_FRAME: raise Blocked('GUEST_FRAME_LIMIT')
    stream.sendall(struct.pack('!I',len(body))+body)


def validate_binding(binding):
    if type(binding) is not dict or set(binding)!=BINDING:
        raise Blocked('GUEST_BINDING_SCHEMA')
    for key in ('job_id','run_id','run_attempt'):
        if type(binding[key]) is not int or not 0<binding[key]<=2**53-1:
            raise Blocked('GUEST_JOB_ID')
    if binding['role'] not in {'LIFE','MICRO','AUDIT','AGGREGATION'}:
        raise Blocked('GUEST_ROLE')
    if type(binding['subject']) is not str or not binding['subject']:
        raise Blocked('GUEST_SUBJECT')
    for key in BINDING-{'job_id','run_id','run_attempt','role','subject'}:
        value=binding[key]
        length=40 if key=='workflow_sha' else 64
        if type(value) is not str or len(value)!=length or any(c not in '0123456789abcdef' for c in value):
            raise Blocked('GUEST_DIGEST')


class GuestClient:
    def __init__(self, local_socket, expected_binding, completion_public_key):
        if local_socket.family!=socket.AF_UNIX: raise Blocked('REMOTE_GUEST_FORBIDDEN')
        validate_binding(expected_binding)
        self.stream,self.binding=local_socket,dict(expected_binding)
        self.key=Ed25519PublicKey.from_public_bytes(completion_public_key)
        self.used=False
        self.buffer=bytearray()

    def execute(self, launch_attestation, timeout=30):
        if self.used or type(timeout) not in (int,float) or not 0<timeout<=30:
            raise Blocked('GUEST_ONE_SHOT_OR_TIMEOUT')
        self.used=True; self.stream.settimeout(timeout)
        request={'version':4,'operation':'fixed-role-execute','binding':self.binding,
                 'launch_attestation':launch_attestation}
        digest=hashlib.sha256(canonical(request)).hexdigest()
        send(self.stream,request)
        ack=receive(self.stream)
        if ack!={'version':4,'status':'ACK','request_sha256':digest}:
            raise Blocked('GUEST_STARTUP_ACK')
        # Completion transport polling deadline is set by trusted lifecycle, not
        # workflow. Use poll_completion() during Job heartbeat to avoid blocking.
        self.request_sha256=digest

    def poll_completion(self, timeout=.1):
        self.stream.settimeout(timeout)
        while len(self.buffer)<4 or len(self.buffer)<4+struct.unpack('!I',self.buffer[:4])[0]:
            if len(self.buffer)>=4 and not 0<struct.unpack('!I',self.buffer[:4])[0]<=MAX_FRAME:
                raise Blocked('GUEST_FRAME_LIMIT')
            try: chunk=self.stream.recv(65536)
            except socket.timeout: return None
            if not chunk: raise Blocked('GUEST_TRUNCATED')
            self.buffer.extend(chunk)
            if len(self.buffer)>MAX_FRAME+4: raise Blocked('GUEST_FRAME_LIMIT')
        size=struct.unpack('!I',self.buffer[:4])[0]
        if len(self.buffer)!=size+4: raise Blocked('GUEST_TRAILING_FRAME')
        raw=bytes(self.buffer[4:]); self.buffer.clear()
        def unique(pairs):
            out={}
            for k,v in pairs:
                if k in out: raise Blocked('GUEST_DUPLICATE_KEY')
                out[k]=v
            return out
        try: envelope=json.loads(raw,object_pairs_hook=unique)
        except (ValueError,UnicodeError): raise Blocked('GUEST_BAD_JSON')
        if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:
            raise Blocked('GUEST_COMPLETION_SCHEMA')
        payload=envelope['payload']
        if type(payload) is not dict or set(payload)!={'version','status','request_sha256','binding','artifacts'}:
            raise Blocked('GUEST_COMPLETION_SCHEMA')
        if payload['version']!=4 or payload['status']!='COMPLETE' or canonical(payload['binding'])!=canonical(self.binding) or payload['request_sha256']!=self.request_sha256:
            raise Blocked('GUEST_COMPLETION_BINDING')
        artifacts=payload['artifacts']
        if type(artifacts) is not list or not artifacts or len(artifacts)>4096:
            raise Blocked('GUEST_ARTIFACTS')
        ids=set()
        for item in artifacts:
            if type(item) is not dict or set(item)!={'object_id','version_id','sha256','size_bytes'}:
                raise Blocked('GUEST_ARTIFACT_SCHEMA')
            object_id=item['object_id']
            # Match the frozen opaque evidence-ref contract, not a guest-selected
            # path or an unverified free-form object name.
            if (type(object_id) is not str or len(object_id)!=64 or
                any(c not in '0123456789abcdef' for c in object_id) or object_id in ids):
                raise Blocked('GUEST_ARTIFACT_ID')
            ids.add(object_id)
            version=item['version_id']
            if (type(version) is not str or not 1<=len(version)<=256 or
                version in {'null','latest'} or
                any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+=./-' for c in version)):
                raise Blocked('GUEST_ARTIFACT_VERSION')
            if (type(item['size_bytes']) is not int or not 0<item['size_bytes']<=2**53-1 or
                type(item['sha256']) is not str or len(item['sha256'])!=64 or
                any(c not in '0123456789abcdef' for c in item['sha256'])):
                raise Blocked('GUEST_ARTIFACT_DIGEST')
        signature=envelope['signature_hex']
        if type(signature) is not str or len(signature)!=128 or any(c not in '0123456789abcdef' for c in signature):
            raise Blocked('GUEST_COMPLETION_SIGNATURE')
        try: self.key.verify(bytes.fromhex(signature),DOMAIN+canonical(payload))
        except Exception: raise Blocked('GUEST_COMPLETION_SIGNATURE')
        return payload


def serve_guest(stream, exact_binding, adapters, verify_launch, signing_key):
    """Guest init dispatch: registry injected from immutable private role image.

    No adapter names, Python modules, commands or paths are taken from request.
    Verification must validate signed consumed permit and live Job capability.
    This generic server ships no research adapter or deployable role image.
    """
    validate_binding(exact_binding)
    request=receive(stream)
    if type(request) is not dict or set(request)!={'version','operation','binding','launch_attestation'} or request['version']!=4 or request['operation']!='fixed-role-execute' or canonical(request['binding'])!=canonical(exact_binding):
        raise Blocked('GUEST_REQUEST_BINDING')
    key=(exact_binding['role'],exact_binding['subject'])
    if key not in adapters or not verify_launch(request['launch_attestation'],exact_binding):
        raise Blocked('GUEST_PERMIT_OR_REGISTRY')
    digest=hashlib.sha256(canonical(request)).hexdigest()
    send(stream,{'version':4,'status':'ACK','request_sha256':digest})
    artifacts=adapters[key]()
    # No aggregate PASS here: this attests guest completion only. Role receipt
    # signing and Final Aggregation remain their separate closed contracts.
    payload={'version':4,'status':'COMPLETE','request_sha256':digest,
             'binding':exact_binding,'artifacts':artifacts}
    send(stream,{'payload':payload,'signature_hex':signing_key.sign(DOMAIN+canonical(payload)).hex()})
