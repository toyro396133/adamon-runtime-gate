"""Purpose-scoped canary injection delegation, distinct from owner root keys."""
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ..runtime.guest import canonical
from ..runtime.microvm import Blocked
DOMAIN=b'ADAMON-NONRESEARCH-GUEST-DELEGATION-V1\0'


def issue_delegation(binding,delegate_public_key,expires_at,owner_signer):
    # Called by owner/supervisor, never Launcher, guest or Workflow.
    from .nonresearch_images import closed_binding
    closed_binding(binding)
    if type(delegate_public_key) is not bytes or len(delegate_public_key)!=32:
        raise Blocked('CANARY_DELEGATION_KEY')
    payload={'version':1,'purpose':'NONRESEARCH_GUEST_INJECTION_ONLY',
             'binding':binding,'delegate_public_key_hex':delegate_public_key.hex(),
             'expires_at':expires_at}
    return {'payload':payload,'signature_hex':owner_signer.sign(DOMAIN+canonical(payload)).hex()}


def verify_delegation(envelope,owner_public_key,expected_binding,clock=time.time):
    from .nonresearch_images import closed_binding
    closed_binding(expected_binding)
    if type(envelope) is not dict or set(envelope)!={'payload','signature_hex'}:
        raise Blocked('CANARY_DELEGATION_SCHEMA')
    payload=envelope['payload']
    if type(payload) is not dict or set(payload)!={'version','purpose','binding','delegate_public_key_hex','expires_at'} or type(payload['version']) is not int or payload['version']!=1 or payload['purpose']!='NONRESEARCH_GUEST_INJECTION_ONLY':
        raise Blocked('CANARY_DELEGATION_SCOPE')
    if canonical(payload['binding'])!=canonical(expected_binding):raise Blocked('CANARY_DELEGATION_BINDING')
    expiry=payload['expires_at'];now=clock()
    if type(expiry) is not int or not now<expiry<=now+300:raise Blocked('CANARY_DELEGATION_EXPIRY')
    try:
        public=bytes.fromhex(payload['delegate_public_key_hex'])
        if len(public)!=32:raise ValueError('size')
        Ed25519PublicKey.from_public_bytes(owner_public_key).verify(bytes.fromhex(envelope['signature_hex']),DOMAIN+canonical(payload))
    except Exception as exc:raise Blocked('CANARY_DELEGATION_SIGNATURE_OR_KEY') from exc
    if public==owner_public_key:raise Blocked('OWNER_ROOT_KEY_NOT_DELEGATE')
    return public,expiry
