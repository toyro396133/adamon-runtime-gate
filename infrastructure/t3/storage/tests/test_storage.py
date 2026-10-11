import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.evidence import EvidenceRef, LocalEncryptedStore, StorageFailure, sha
from infrastructure.t3.storage.s3 import S3EvidenceWriter, S3EvidenceReader

class FakeS3:
    """Contract fake, never asserted as AWS/security-service proof."""
    def __init__(self):
        self.data = {}
        self.parts = {}
        self.calls = []
        self.versioning = 'Enabled'
        self.public = True
        self.mode = 'COMPLIANCE'
        self.days = 365
        self.kms = 'arn:aws:kms:region:account:key/test'
        self.wrong_version = False
        self.corrupt = False
        self.part_corrupt = False
        self.no_version = False
        self.tls_policy = True
    def get_bucket_versioning(self, **kw): return {'Status':self.versioning}
    def get_public_access_block(self, **kw): return {'PublicAccessBlockConfiguration':dict.fromkeys(('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'),self.public)}
    def get_object_lock_configuration(self, **kw): return {'ObjectLockConfiguration':{'ObjectLockEnabled':'Enabled','Rule':{'DefaultRetention':{'Mode':self.mode,'Days':self.days}}}}
    def get_bucket_encryption(self, **kw): return {'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms','KMSMasterKeyID':self.kms}}]}}
    def get_bucket_policy(self, **kw):
        arn = 'arn:aws:s3:::'+kw['Bucket']
        return {'Policy':json.dumps({'Statement':[{'Effect':'Deny','Principal':'*','Action':'s3:*','Resource':[arn,arn+'/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}] if self.tls_policy else []})}
    def put_object(self, **kw):
        self.calls.append(('put',kw))
        if kw['Key'] in self.data or kw.get('IfNoneMatch') != '*': raise RuntimeError('conditional conflict')
        self.data[kw['Key']] = (kw['Body'],kw)
        return {'VersionId':'null' if self.no_version else 'pinned-version'}
    def create_multipart_upload(self, **kw):
        self.calls.append(('create',kw)); self.multipart_args=kw
        return {'UploadId':'retained-upload'}
    def upload_part(self, **kw):
        self.calls.append(('part',kw)); self.parts[kw['PartNumber']]=kw['Body']
        return {'ETag':'not-a-sha','ChecksumSHA256':'wrong' if self.part_corrupt else kw['ChecksumSHA256']}
    def complete_multipart_upload(self, **kw):
        self.calls.append(('complete',kw))
        data = b''.join(self.parts[index] for index in sorted(self.parts))
        return self.put_object(**self.multipart_args,Body=data,IfNoneMatch=kw['IfNoneMatch'])
    def head_object(self, **kw):
        data, metadata=self.data[kw['Key']]
        return {'VersionId':'pinned-version','ContentLength':len(data),'ServerSideEncryption':'aws:kms', 'SSEKMSKeyId':self.kms,'ObjectLockMode':self.mode,'ObjectLockRetainUntilDate':metadata['ObjectLockRetainUntilDate']}
    def get_object(self, **kw):
        self.calls.append(('get',kw))
        data=self.data[kw['Key']][0]
        return {'VersionId':'wrong' if self.wrong_version else 'pinned-version','Body':io.BytesIO(data+b'altered' if self.corrupt else data)}

class LocalTests(unittest.TestCase):
    def setUp(self):
        cache=Path(tempfile.gettempdir())
        self.tmp=tempfile.TemporaryDirectory(dir=cache)
        self.key=Ed25519PrivateKey.generate()
        self.db=Path(self.tmp.name)/'encrypted.sqlite'
        self.store=LocalEncryptedStore(self.db,b'e'*32,self.key,'synthetic-key')
    def tearDown(self): self.tmp.cleanup()
    def test_encrypted_roundtrip(self):
        data=b'SYNTHETIC-PRIVATE-CANARY'
        receipt=self.store.put(data)
        self.assertEqual(self.store.read(receipt),data)
        self.assertNotIn(data,self.db.read_bytes())
    def test_reopen_persistence(self):
        receipt=self.store.put(b'restart')
        reopened=LocalEncryptedStore(self.db,b'e'*32,self.key,'synthetic-key')
        self.assertEqual(reopened.read(receipt),b'restart')
    def test_duplicate_cannot_overwrite(self):
        receipt=self.store.put(b'same')
        with self.assertRaises(StorageFailure):self.store.put(b'same')
        self.assertEqual(self.store.read(receipt),b'same')
    def test_atomic_concurrent_create(self):
        def attempt(_):
            try:self.store.put(b'race');return True
            except StorageFailure:return False
        with ThreadPoolExecutor(max_workers=6) as pool: results=list(pool.map(attempt,range(12)))
        self.assertEqual(sum(results),1)
    def test_invalid_signature(self):
        receipt=self.store.put(b'bytes')
        with self.assertRaises(StorageFailure):self.store.read(replace(receipt,signature=base64.b64encode(b'0'*64).decode()))
    def test_wrong_signer(self):
        receipt=self.store.put(b'bytes')
        with self.assertRaises(StorageFailure):receipt.verify(Ed25519PrivateKey.generate().public_key(),'synthetic-key')
    def test_version_substitution(self):
        receipt=self.store.put(b'bytes')
        with self.assertRaises(StorageFailure):self.store.read(replace(receipt,reference=replace(receipt.reference,version_id='another')))
    def test_latest_null_rejected(self):
        for version in ('','null','latest'):
            with self.assertRaises(StorageFailure):EvidenceRef(sha(b''),version,sha(b''),0)
    def test_update_delete_forbidden(self):
        self.store.put(b'original')
        with sqlite3.connect(self.db) as con:
            for sql in ('DELETE FROM versions','UPDATE versions SET nonce=X\'00\''):
                with self.assertRaises(sqlite3.IntegrityError):con.execute(sql)
    def test_administrator_tampering_detected(self):
        receipt=self.store.put(b'original')
        with sqlite3.connect(self.db) as con:
            con.execute('DROP TRIGGER no_update');con.execute("UPDATE versions SET ciphertext=X'00'")
        with self.assertRaises(StorageFailure):self.store.read(receipt)
    def test_wrong_encryption_key(self):
        receipt=self.store.put(b'original')
        bad=LocalEncryptedStore(self.db,b'f'*32,self.key,'synthetic-key')
        with self.assertRaises(StorageFailure):bad.read(receipt)
    def test_partial_preserved(self):
        for state in ('SEALED_PARTIAL','CRASH_INCOMPLETE'):
            data=state.encode();receipt=self.store.put(data,state)
            self.assertEqual(receipt.state,state);self.assertEqual(self.store.read(receipt),data)
    def test_invalid_size(self):
        with self.assertRaises(StorageFailure):EvidenceRef(sha(b''),'version',sha(b''),True)

class RemoteContractTests(unittest.TestCase):
    def setUp(self):
        self.client=FakeS3();self.key=Ed25519PrivateKey.generate()
        self.writer=S3EvidenceWriter(self.client,bucket='private-test',kms_key_arn=self.client.kms,
            authority_sha256='a'*64,attempt_id='attempt1',signer=self.key,signer_key_id='broker')
    def ready(self):self.writer.verify_configuration()
    def test_preflight_required(self):
        with self.assertRaises(StorageFailure):self.writer.put(b'bytes')
    def test_roundtrip_exact_pinned_version(self):
        self.ready();receipt=self.writer.put(b'bytes')
        reader=S3EvidenceReader(self.client,bucket='private-test',authority_sha256='a'*64,attempt_id='attempt1',trusted_key=self.key.public_key(),trusted_key_id='broker')
        self.assertEqual(reader.read(receipt),b'bytes')
        self.assertTrue(all(c[1]['VersionId']=='pinned-version' for c in self.client.calls if c[0]=='get'))
    def test_configuration_failures(self):
        for field,value in (('versioning','Suspended'),('public',False),('mode','GOVERNANCE'),('days',364),('kms','wrong'),('tls_policy',False)):
            fresh=FakeS3();setattr(fresh,field,value);self.writer.client=fresh
            with self.assertRaises(StorageFailure):self.writer.verify_configuration()
    def test_conditional_duplicate_preserves(self):
        self.ready();self.writer.put(b'original')
        with self.assertRaises(StorageFailure):self.writer.put(b'original')
        self.assertEqual(next(iter(self.client.data.values()))[0],b'original')
    def test_null_version_rejected(self):
        self.ready();self.client.no_version=True
        with self.assertRaises(StorageFailure):self.writer.put(b'bytes')
    def test_readback_version_substitution(self):
        self.ready();self.client.wrong_version=True
        with self.assertRaises(StorageFailure):self.writer.put(b'bytes')
    def test_readback_corruption(self):
        self.ready();self.client.corrupt=True
        with self.assertRaises(StorageFailure):self.writer.put(b'bytes')
    def test_multipart_conditional_and_checksums(self):
        self.ready();self.writer.PART_SIZE=5
        receipt=self.writer.put(b'12byteshere')
        self.assertEqual(receipt.reference.size_bytes,11)
        complete=next(c[1] for c in self.client.calls if c[0]=='complete')
        self.assertEqual(complete['IfNoneMatch'],'*')
        self.assertEqual(len(complete['MultipartUpload']['Parts']),3)
    def test_failed_multipart_retained(self):
        self.ready();self.writer.PART_SIZE=5;self.client.part_corrupt=True
        with self.assertRaises(StorageFailure):self.writer.put(b'12byteshere')
        self.assertIn(1,self.client.parts)
        self.assertFalse(any(c[0]=='complete' for c in self.client.calls))
    def test_partial_reviewer_cannot_pass_complete(self):
        self.ready();receipt=self.writer.put(b'partial','SEALED_PARTIAL')
        reader=S3EvidenceReader(self.client,bucket='private-test',authority_sha256='a'*64,attempt_id='attempt1',trusted_key=self.key.public_key(),trusted_key_id='broker')
        with self.assertRaises(StorageFailure):reader.read(receipt)
        self.assertEqual(reader.read(receipt,require_complete=False),b'partial')
    def test_wrong_namespace(self):
        with self.assertRaises(StorageFailure):S3EvidenceReader(self.client,bucket='test',authority_sha256='a'*64,attempt_id='../',trusted_key=self.key.public_key(),trusted_key_id='key')
    def test_other_campaign_namespace_rejected(self):
        self.ready();receipt=self.writer.put(b'bytes')
        reader=S3EvidenceReader(self.client,bucket='private-test',authority_sha256='b'*64,attempt_id='attempt1',trusted_key=self.key.public_key(),trusted_key_id='broker')
        before=len(self.client.calls)
        with self.assertRaises(StorageFailure):reader.read(receipt)
        self.assertEqual(len(self.client.calls),before)
    def test_other_attempt_namespace_rejected(self):
        self.ready();receipt=self.writer.put(b'bytes')
        reader=S3EvidenceReader(self.client,bucket='private-test',authority_sha256='a'*64,attempt_id='attempt2',trusted_key=self.key.public_key(),trusted_key_id='broker')
        with self.assertRaises(StorageFailure):reader.read(receipt)
    def test_short_retention_rejected(self):
        with self.assertRaises(StorageFailure):S3EvidenceWriter(self.client,bucket='test',kms_key_arn=self.client.kms,authority_sha256='a'*64,attempt_id='attempt1',signer=self.key,signer_key_id='broker',retention_until=datetime.now(timezone.utc)+timedelta(days=1))

if __name__=='__main__':unittest.main()
