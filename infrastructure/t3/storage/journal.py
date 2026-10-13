"""Owner-local publication journal of signed exact versions, never latest/cache.

Needed for repeated original bytes (replay and before/after idempotence). It
stores only immutable references, re-verifies signatures and downloads exact
versions on every reuse. AWS/S3 denial proof remains live PF-07, not these tests.
A crash before a remote version receipt is durably journaled stays fail-closed;
no latest-object lookup or silent replacement is permitted.
"""
import json,sqlite3
from .evidence import EvidenceRef,SealedEvidence,StorageFailure,canonical,sha
from .s3 import S3EvidenceReader
from .s3_protected import ProtectedS3EvidenceWriter

class JournaledS3Store:
    def __init__(self,writer,reader,*,ledger):
        if not isinstance(writer,ProtectedS3EvidenceWriter) or not isinstance(reader,S3EvidenceReader):
            raise StorageFailure('concrete protected writer/exact-version reader required')
        if (writer.bucket,writer.prefix,writer.kms,writer.key_id)!=(reader.bucket,reader.prefix,reader.kms,reader.key_id) or writer.signer.public_key().public_bytes_raw()!=reader.key.public_bytes_raw():
            raise StorageFailure('publication journal writer/reader identity mismatch')
        self.writer,self.reader,self.ledger=writer,reader,ledger
        self.scope=sha(canonical({'bucket':writer.bucket,'prefix':writer.prefix}))
        with self.connect() as c:
            c.executescript('CREATE TABLE IF NOT EXISTS signed_versions(scope TEXT,digest TEXT,envelope BLOB NOT NULL,PRIMARY KEY(scope,digest)); CREATE TRIGGER IF NOT EXISTS signed_versions_no_update BEFORE UPDATE ON signed_versions BEGIN SELECT RAISE(ABORT,"immutable"); END; CREATE TRIGGER IF NOT EXISTS signed_versions_no_delete BEFORE DELETE ON signed_versions BEGIN SELECT RAISE(ABORT,"immutable"); END;')
    def connect(self):return sqlite3.connect(self.ledger,timeout=15)
    def read(self,envelope):return self.reader.read(envelope,require_complete=False)
    def put(self,data,state='SEALED_COMPLETE'):
        # Preserve raw writer's existing create-only semantics.
        return self.writer.put(data,state=state)
    def put_exact(self,data,state='SEALED_COMPLETE'):
        if type(data) is not bytes or not data or state not in ('SEALED_COMPLETE','SEALED_PARTIAL','CRASH_INCOMPLETE'):
            raise StorageFailure('closed original journal byte/state contract')
        self.writer.verify_configuration()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT envelope FROM signed_versions WHERE scope=? AND digest=?',(self.scope,sha(data))).fetchone()
            if row is None:
                envelope=self.writer.put(data,state=state)
                envelope.verify(self.reader.key,self.reader.key_id)
                if envelope.storage_scope_sha256!=self.scope or self.read(envelope)!=data:
                    raise StorageFailure('new publication exact-byte verification failed')
                c.execute('INSERT INTO signed_versions VALUES(?,?,?)',(self.scope,sha(data),canonical({**envelope.payload(),'signature':envelope.signature})))
                return envelope
            def unique(pairs):
                value={}
                for key,item in pairs:
                    if key in value:raise StorageFailure('duplicate journal field')
                    value[key]=item
                return value
            try:
                p=json.loads(row[0],object_pairs_hook=unique)
                if set(p)!={'version','reference','state','retention_until','signer_key_id','signature','storage_scope_sha256'} or type(p['version']) is not int or p['version']!=1:raise StorageFailure('journal envelope shape')
                envelope=SealedEvidence(EvidenceRef(**p['reference']),p['state'],p['retention_until'],p['signer_key_id'],p['signature'],p['storage_scope_sha256'])
            except (ValueError,TypeError,KeyError) as exc:raise StorageFailure('invalid journal original') from exc
            envelope.verify(self.reader.key,self.reader.key_id)
            if envelope.state!=state or envelope.storage_scope_sha256!=self.scope or envelope.reference.sha256!=sha(data) or self.read(envelope)!=data:
                raise StorageFailure('journal state/scope/exact-byte reuse mismatch')
            return envelope
