"""Signed bounded local guest provisioning. No command, path or module input."""
import hashlib
import time
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .guest import canonical, validate_binding
from .microvm import Blocked

DOMAIN = b'ADAMON-P4V4-GUEST-INJECTION\0'
MAX_SOURCE_BYTES = 64*1024*1024


def issue(binding, source_bytes, fixture_bytes, completion_public_key, expires_at, signer):
    validate_binding(binding)
    if (type(source_bytes) is not bytes or type(fixture_bytes) is not bytes or
        len(source_bytes)+len(fixture_bytes)>MAX_SOURCE_BYTES):
        raise Blocked('INJECTION_SIZE')
    if hashlib.sha256(source_bytes).hexdigest()!=binding['source_sha256'] or hashlib.sha256(fixture_bytes).hexdigest()!=binding['fixture_sha256']:
        raise Blocked('INJECTION_SOURCE_PIN')
    if type(completion_public_key) is not bytes or len(completion_public_key)!=32:
        raise Blocked('INJECTION_KEY')
    payload={'version':4,'binding':binding,'source_size':len(source_bytes),
             'fixture_size':len(fixture_bytes),'completion_spki_hex':completion_public_key.hex(),
             'expires_at':expires_at}
    validate_payload(payload)
    return {'payload':payload,'signature_hex':signer.sign(DOMAIN+canonical(payload)).hex()}


def validate_payload(payload):
    if type(payload) is not dict or set(payload)!={'version','binding','source_size','fixture_size','completion_spki_hex','expires_at'} or type(payload['version']) is not int or payload['version']!=4:
        raise Blocked('INJECTION_SCHEMA')
    validate_binding(payload['binding'])
    if any(type(payload[k]) is not int or payload[k]<0 for k in ('source_size','fixture_size')) or payload['source_size']+payload['fixture_size']>MAX_SOURCE_BYTES:
        raise Blocked('INJECTION_SIZE')
    if type(payload['expires_at']) is not int or payload['expires_at']<=0:
        raise Blocked('INJECTION_EXPIRY')
    key=payload['completion_spki_hex']
    if type(key) is not str or len(key)!=64 or any(c not in '0123456789abcdef' for c in key):
        raise Blocked('INJECTION_KEY')


class InjectionVerifier:
    """One-use guest-side capability from immutable image owner's public key."""
    def __init__(self, owner_public_key, expected_binding, completion_public_key, clock=time.time):
        validate_binding(expected_binding)
        self.key=Ed25519PublicKey.from_public_bytes(owner_public_key)
        if type(completion_public_key) is not bytes or len(completion_public_key)!=32:
            raise Blocked('INJECTION_KEY')
        self.completion_key=completion_public_key.hex()
        self.binding=dict(expected_binding); self.clock=clock; self.used=False; self._lock=threading.Lock()

    def consume(self, envelope, source_bytes, fixture_bytes):
        with self._lock:
            return self._consume(envelope, source_bytes, fixture_bytes)

    def _consume(self, envelope, source_bytes, fixture_bytes):
        if self.used: raise Blocked('INJECTION_REPLAY')
        if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:
            raise Blocked('INJECTION_ENVELOPE')
        p=envelope['payload']; validate_payload(p)
        if p['completion_spki_hex']!=self.completion_key: raise Blocked('INJECTION_COMPLETION_KEY_BINDING')
        if canonical(p['binding'])!=canonical(self.binding): raise Blocked('INJECTION_BINDING')
        if not self.clock()<p['expires_at']<=self.clock()+300: raise Blocked('INJECTION_EXPIRED')
        sig=envelope['signature_hex']
        if type(sig) is not str or len(sig)!=128 or any(c not in '0123456789abcdef' for c in sig): raise Blocked('INJECTION_SIGNATURE')
        try: self.key.verify(bytes.fromhex(sig),DOMAIN+canonical(p))
        except Exception: raise Blocked('INJECTION_SIGNATURE')
        if type(source_bytes) is not bytes or type(fixture_bytes) is not bytes or len(source_bytes)!=p['source_size'] or len(fixture_bytes)!=p['fixture_size']:
            raise Blocked('INJECTION_LENGTH')
        if hashlib.sha256(source_bytes).hexdigest()!=self.binding['source_sha256'] or hashlib.sha256(fixture_bytes).hexdigest()!=self.binding['fixture_sha256']:
            raise Blocked('INJECTION_SOURCE_PIN')
        self.used=True
        # Bytes are returned to a closed immutable-image adapter, never extracted
        # using guest-supplied filenames or executed as arbitrary Python/shell.
        return source_bytes, fixture_bytes


class VerifiedGuestDispatch:
    """Closed adapter image binds actual source bytes and signing key to launch.

    Construction occurs in immutable guest init, not from request fields. Source
    bytes are pinned image assets, not an arbitrary uploaded executable/archive.
    This service is reusable by nonresearch canaries and future approved images.
    """
    def __init__(self, binding, owner_public_key, signing_key, source_bytes,
                 fixture_bytes, adapters, clock=time.time):
        validate_binding(binding)
        if type(source_bytes) is not bytes or type(fixture_bytes) is not bytes or len(source_bytes)+len(fixture_bytes)>MAX_SOURCE_BYTES:
            raise Blocked('GUEST_IMAGE_SOURCE_SIZE')
        if hashlib.sha256(source_bytes).hexdigest()!=binding['source_sha256'] or hashlib.sha256(fixture_bytes).hexdigest()!=binding['fixture_sha256']:
            raise Blocked('GUEST_IMAGE_SOURCE_PIN')
        if set(adapters)!={(binding['role'],binding['subject'])}:
            raise Blocked('GUEST_IMAGE_CLOSED_REGISTRY')
        self.binding=dict(binding); self.signing_key=signing_key
        self.source=source_bytes; self.fixture=fixture_bytes; self.adapters=dict(adapters)
        self.consumed=None
        self.verifier=InjectionVerifier(owner_public_key,binding,
            signing_key.public_key().public_bytes_raw(),clock)

    def serve(self, stream):
        from .guest import serve_guest
        def verify(envelope, expected):
            if canonical(expected)!=canonical(self.binding): raise Blocked('GUEST_IMAGE_BINDING')
            self.consumed=self.verifier.consume(envelope,self.source,self.fixture)
            return True
        key=(self.binding['role'],self.binding['subject'])
        def run_verified():
            if self.consumed is None: raise Blocked('GUEST_IMAGE_NOT_PROVISIONED')
            # Only the closed compiled-in adapter executes. It receives the very
            # bytes consumed and verified, not paths or dynamically loaded code.
            return self.adapters[key](*self.consumed)
        return serve_guest(stream,self.binding,{key:run_verified},verify,self.signing_key)


AuthenticatedGuestImage=VerifiedGuestDispatch
