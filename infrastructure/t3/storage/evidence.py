"""Byte-only private evidence storage. No research computation or caller paths."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b'ADAMON-T3-SEALED-EVIDENCE-V1\x00'
HEX = re.compile(r'^[0-9a-f]{64}$')

class StorageFailure(RuntimeError):
    """Failure requires quarantining source volume, never deleting original bytes."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

@dataclass(frozen=True)
class EvidenceRef:
    object_id: str
    version_id: str
    sha256: str
    size_bytes: int

    def __post_init__(self):
        if not HEX.fullmatch(self.object_id) or self.object_id != self.sha256:
            raise StorageFailure('invalid content address')
        if not isinstance(self.version_id, str) or not self.version_id or self.version_id in ('null', 'latest') or len(self.version_id) > 1024:
            raise StorageFailure('exact non-null version required')
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise StorageFailure('invalid size')

@dataclass(frozen=True)
class SealedEvidence:
    reference: EvidenceRef
    state: str
    retention_until: str
    signer_key_id: str
    signature: str
    storage_scope_sha256: str = sha(b'LOCAL_SYNTHETIC_ONLY')

    def payload(self):
        return {'version': 1, 'reference': asdict(self.reference), 'state': self.state,
                'retention_until': self.retention_until, 'signer_key_id': self.signer_key_id,
                'storage_scope_sha256': self.storage_scope_sha256}

    def verify(self, key: Ed25519PublicKey, expected_key_id: str) -> None:
        if not HEX.fullmatch(self.storage_scope_sha256):
            raise StorageFailure('invalid signed storage scope')
        if self.signer_key_id != expected_key_id or self.state not in ('SEALED_COMPLETE', 'SEALED_PARTIAL', 'CRASH_INCOMPLETE'):
            raise StorageFailure('untrusted signing identity or state')
        try:
            key.verify(base64.b64decode(self.signature, validate=True), DOMAIN + canonical(self.payload()))
        except Exception as exc:
            raise StorageFailure('invalid evidence signature') from exc


def signed(reference, state, retention_until, key_id, signer, storage_scope_sha256=sha(b'LOCAL_SYNTHETIC_ONLY')):
    envelope = SealedEvidence(reference, state, retention_until, key_id, '', storage_scope_sha256)
    if state not in ('SEALED_COMPLETE', 'SEALED_PARTIAL', 'CRASH_INCOMPLETE'):
        raise StorageFailure('unknown sealing state')
    signature = base64.b64encode(signer.sign(DOMAIN + canonical(envelope.payload()))).decode('ascii')
    return SealedEvidence(reference, state, retention_until, key_id, signature, storage_scope_sha256)

class LocalEncryptedStore:
    """Synthetic local cryptographic test store, NOT S3 Object Lock or OS immutability.

    Administrator can alter SQLite. Ed25519/AES-GCM detect changed pinned bytes;
    no API can overwrite/delete/replace a version. Keys are caller-injected memory,
    never serialized. This store cannot qualify production storage preflight.
    """
    capability = 'LOCAL_SYNTHETIC_ONLY_NOT_OBJECT_LOCK'

    def __init__(self, database: Path, encryption_key: bytes, signer: Ed25519PrivateKey, key_id: str, *, storage_scope_sha256=sha(b'LOCAL_SYNTHETIC_ONLY')):
        if len(encryption_key) != 32 or not key_id:
            raise StorageFailure('invalid key configuration')
        self.database, self.aead, self.signer, self.key_id = database, AESGCM(encryption_key), signer, key_id
        if type(storage_scope_sha256) is not str or not HEX.fullmatch(storage_scope_sha256):
            raise StorageFailure('exact storage scope required')
        self.storage_scope_sha256 = storage_scope_sha256
        self.public_key = signer.public_key()
        with self._connect() as connection:
            connection.executescript('''
        CREATE TABLE IF NOT EXISTS versions (object_id TEXT PRIMARY KEY, version_id TEXT UNIQUE NOT NULL,
        nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, receipt BLOB NOT NULL);
        CREATE TRIGGER IF NOT EXISTS no_update BEFORE UPDATE ON versions BEGIN SELECT RAISE(ABORT,'immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete BEFORE DELETE ON versions BEGIN SELECT RAISE(ABORT,'immutable'); END;
        ''')
        os.chmod(database, 0o600)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=15)
        try:
            connection.execute('PRAGMA synchronous=FULL')
            with connection:
                yield connection
        finally:
            connection.close()

    def put(self, data: bytes, state='SEALED_COMPLETE') -> SealedEvidence:
        if type(data) is not bytes:
            raise StorageFailure('bytes required')
        reference = EvidenceRef(sha(data), str(uuid.uuid4()), sha(data), len(data))
        until = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        envelope = signed(reference, state, until, self.key_id, self.signer, self.storage_scope_sha256)
        nonce = os.urandom(12)
        aad = canonical(envelope.payload())
        ciphertext = self.aead.encrypt(nonce, data, aad)
        try:
            with self._connect() as con:
                con.execute('INSERT INTO versions VALUES(?,?,?,?,?)', (reference.object_id, reference.version_id, nonce, ciphertext, canonical({**envelope.payload(), 'signature': envelope.signature})))
        except sqlite3.IntegrityError as exc:
            raise StorageFailure('create-only conflict; original retained') from exc
        if self.read(envelope) != data:
            raise StorageFailure('readback failed; quarantine source')
        return envelope

    def read(self, envelope: SealedEvidence) -> bytes:
        envelope.verify(self.public_key, self.key_id)
        with self._connect() as con:
            row = con.execute('SELECT nonce,ciphertext,receipt FROM versions WHERE object_id=? AND version_id=?', (envelope.reference.object_id, envelope.reference.version_id)).fetchone()
        if row is None or row[2] != canonical({**envelope.payload(), 'signature': envelope.signature}):
            raise StorageFailure('missing or mismatched exact sealed version')
        try:
            data = self.aead.decrypt(row[0], row[1], canonical(envelope.payload()))
        except Exception as exc:
            raise StorageFailure('encrypted evidence integrity failed') from exc
        if sha(data) != envelope.reference.sha256 or len(data) != envelope.reference.size_bytes:
            raise StorageFailure('source hash/size mismatch')
        return data

    def put_exact(self, data: bytes, state='SEALED_COMPLETE') -> SealedEvidence:
        """Atomically reuse an authenticated exact version, never upgrade state.

        This local-only primitive recovers interrupted inventory publication.
        It does not change put's create-only contract or qualify Object Lock.
        """
        if type(data) is not bytes or state not in ('SEALED_COMPLETE','SEALED_PARTIAL','CRASH_INCOMPLETE'):
            raise StorageFailure('exact byte/state contract')
        object_id=sha(data)
        with self._connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT nonce,ciphertext,receipt FROM versions WHERE object_id=?',(object_id,)).fetchone()
            if row is not None:
                p=json.loads(row[2])
                if set(p)!={'version','reference','state','retention_until','signer_key_id','signature','storage_scope_sha256'} or p['version']!=1:
                    raise StorageFailure('exact reuse receipt shape')
                envelope=SealedEvidence(EvidenceRef(**p['reference']),p['state'],p['retention_until'],p['signer_key_id'],p['signature'],p['storage_scope_sha256'])
                envelope.verify(self.public_key,self.key_id)
                if envelope.state!=state or envelope.storage_scope_sha256!=self.storage_scope_sha256:
                    raise StorageFailure('exact reuse state/scope mismatch')
                try:original=self.aead.decrypt(row[0],row[1],canonical(envelope.payload()))
                except Exception as exc:raise StorageFailure('exact reuse encryption integrity') from exc
                if original!=data or envelope.reference.sha256!=object_id or envelope.reference.size_bytes!=len(data):
                    raise StorageFailure('exact reuse original mismatch')
                return envelope
            ref=EvidenceRef(object_id,str(uuid.uuid4()),object_id,len(data))
            envelope=signed(ref,state,(datetime.now(timezone.utc)+timedelta(days=365)).isoformat(),self.key_id,self.signer,self.storage_scope_sha256)
            nonce=os.urandom(12)
            con.execute('INSERT INTO versions VALUES(?,?,?,?,?)',(object_id,ref.version_id,nonce,self.aead.encrypt(nonce,data,canonical(envelope.payload())),canonical({**envelope.payload(),'signature':envelope.signature})))
        if self.read(envelope)!=data:raise StorageFailure('exact reuse readback failed')
        return envelope
