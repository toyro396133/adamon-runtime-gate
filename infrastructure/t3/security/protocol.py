"""Strict canonical Ed25519 envelopes and channel-bound one-use challenges."""
import hashlib
import json
import secrets
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

class Denied(ValueError):
    pass

def canonical(value):
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= 2**53-1:
            return
        if type(item) is str and item.isascii():
            return
        if type(item) is list:
            for v in item: check(v)
            return
        if type(item) is dict and all(type(k) is str and k.isascii() for k in item):
            for v in item.values(): check(v)
            return
        raise Denied('noncanonical value')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise Denied('duplicate field')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('constant')))
        if canonical(value) != raw: raise Denied('noncanonical bytes')
        return value
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Denied('invalid JSON') from exc

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def spki_digest(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                          serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

def sign(payload, key, key_id, domain):
    return {'payload': payload, 'key_id': key_id,
            'signature': key.sign(domain.encode('ascii')+b'\n'+canonical(payload)).hex()}

def verify(envelope, pinned_keys, domain):
    if type(envelope) is not dict or set(envelope) != {'payload','key_id','signature'}:
        raise Denied('envelope shape')
    if type(envelope['key_id']) is not str: raise Denied('key ID type')
    key = pinned_keys.get(envelope['key_id'])
    if not isinstance(key, Ed25519PublicKey): raise Denied('untrusted signer')
    try:
        signature = bytes.fromhex(envelope['signature'])
        if len(signature) != 64: raise ValueError('signature size')
        key.verify(signature, domain.encode('ascii')+b'\n'+canonical(envelope['payload']))
    except Exception as exc:
        raise Denied('invalid signature') from exc
    return envelope['payload']

class Challenges:
    """Single-use under a lock; consumed even if a proof fails."""
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.pending = clock, threading.Lock(), {}
    def issue(self, session, exporter_sha256, request_sha256):
        proof = dict(session_id=session, challenge_hex=secrets.token_hex(32),
                     exporter_sha256=exporter_sha256, request_sha256=request_sha256)
        with self.lock:
            if session in self.pending: raise Denied('challenge already outstanding')
            self.pending[session] = (proof, self.clock()+30)
        return proof
    def consume(self, proof, signature, public_key):
        with self.lock:
            entry = self.pending.pop(proof.get('session_id'), None)
        if entry is None or self.clock() >= entry[1] or proof != entry[0]:
            raise Denied('expired/replayed/channel-mismatched challenge')
        verify(dict(payload=proof, key_id='channel', signature=signature),
               {'channel': public_key}, 'ADAMON-P4V3-CLIENT-PROOF')
