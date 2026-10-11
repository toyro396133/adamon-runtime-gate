"""S3 SSE-KMS/Object Lock adapter; injected SDK client, no credentials in code.

No cloud operation runs at import. Deployment requires separate owner approval.
Only byte transfer occurs outside research Jobs. Writer and reviewer use distinct
IAM clients. The SDK must support conditional CompleteMultipartUpload.
"""
from __future__ import annotations
import base64
from datetime import datetime, timedelta, timezone
from .evidence import EvidenceRef, SealedEvidence, StorageFailure, canonical, sha, signed

class S3EvidenceWriter:
    PART_SIZE = 32 * 1024 * 1024

    def __init__(self, client, *, bucket, kms_key_arn, authority_sha256, attempt_id,
                 signer, signer_key_id, retention_until=None):
        from .evidence import HEX
        if not HEX.fullmatch(authority_sha256) or not attempt_id or not attempt_id.isalnum() or len(attempt_id) > 64:
            raise StorageFailure('unapproved storage namespace')
        if not bucket or not kms_key_arn.startswith('arn:aws:kms:'):
            raise StorageFailure('private bucket and exact KMS ARN required')
        self.client, self.bucket, self.kms = client, bucket, kms_key_arn
        self.prefix = authority_sha256 + '/' + attempt_id + '/'
        self.context = base64.b64encode(canonical({'authority': authority_sha256, 'attempt': attempt_id})).decode()
        self.signer, self.key_id = signer, signer_key_id
        self.retention_until = retention_until or datetime.now(timezone.utc) + timedelta(days=365)
        if self.retention_until.tzinfo is None or self.retention_until < datetime.now(timezone.utc) + timedelta(days=364, hours=23):
            raise StorageFailure('retention must be >=365 days; no shortened horizon')
        self.preflight_passed = False

    def verify_configuration(self):
        """Read-only real API checks; does NOT prove IAM/KMS denial or multipart races."""
        self.preflight_passed = False
        c, b = self.client, self.bucket
        try:
            if c.get_bucket_versioning(Bucket=b).get('Status') != 'Enabled':
                raise StorageFailure('versioning unavailable')
            block = c.get_public_access_block(Bucket=b)['PublicAccessBlockConfiguration']
            if not all(block.get(k) is True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')):
                raise StorageFailure('public access not fully blocked')
            config = c.get_object_lock_configuration(Bucket=b)['ObjectLockConfiguration']
            rule = config['Rule']['DefaultRetention']
            days = rule.get('Days', rule.get('Years', 0) * 365)
            if config.get('ObjectLockEnabled') != 'Enabled' or rule.get('Mode') != 'COMPLIANCE' or days < 365:
                raise StorageFailure('compliance retention unavailable')
            rules = c.get_bucket_encryption(Bucket=b)['ServerSideEncryptionConfiguration']['Rules']
            if not any(r.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm') == 'aws:kms'
                       and r['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID') == self.kms for r in rules):
                raise StorageFailure('exact default KMS key unavailable')
            # TLS policy must explicitly deny insecure transport for this bucket
            # and all of its objects, with no extra condition weakening the deny.
            import json
            policy = json.loads(c.get_bucket_policy(Bucket=b)['Policy'])
            bucket_arn = 'arn:aws:s3:::' + b
            def tls_deny(s):
                resources = s.get('Resource', [])
                resources = [resources] if isinstance(resources, str) else resources
                actions = s.get('Action', [])
                actions = [actions] if isinstance(actions, str) else actions
                return (s.get('Effect') == 'Deny' and s.get('Principal') in ('*', {'AWS':'*'})
                        and ('s3:*' in actions or '*' in actions)
                        and bucket_arn in resources and bucket_arn+'/*' in resources
                        and s.get('Condition') == {'Bool': {'aws:SecureTransport':'false'}})
            if not any(tls_deny(s) for s in policy.get('Statement', [])):
                raise StorageFailure('explicit all-principal TLS deny missing')
        except StorageFailure:
            raise
        except Exception as exc:
            raise StorageFailure('storage configuration cannot be verified') from exc
        self.preflight_passed = True
        return {'configuration': 'API_VERIFIED', 'write_race': 'UNVERIFIED', 'kms_iam_denials': 'UNVERIFIED', 'reviewer_retrieval': 'UNVERIFIED'}

    def put(self, data: bytes, state='SEALED_COMPLETE') -> SealedEvidence:
        if not self.preflight_passed or type(data) is not bytes:
            raise StorageFailure('read-only configuration preflight required')
        if state not in ('SEALED_COMPLETE', 'SEALED_PARTIAL', 'CRASH_INCOMPLETE'):
            raise StorageFailure('unknown sealing state')
        key = self.prefix + sha(data)
        args = dict(Bucket=self.bucket, Key=key, ServerSideEncryption='aws:kms', SSEKMSKeyId=self.kms,
                    SSEKMSEncryptionContext=self.context, ObjectLockMode='COMPLIANCE',
                    ObjectLockRetainUntilDate=self.retention_until)
        try:
            if len(data) <= self.PART_SIZE:
                result = self.client.put_object(**args, Body=data, IfNoneMatch='*',
                    ChecksumSHA256=base64.b64encode(bytes.fromhex(sha(data))).decode())
            else:
                result = self._multipart(args, data)
            version = result.get('VersionId')
            reference = EvidenceRef(sha(data), version, sha(data), len(data))
            # Pin version, never infer SHA256 from ETag.
            head = self.client.head_object(Bucket=self.bucket, Key=key, VersionId=version)
            if (head.get('VersionId') != version or head.get('ContentLength') != len(data)
                or head.get('ServerSideEncryption') != 'aws:kms' or head.get('SSEKMSKeyId') != self.kms
                or head.get('ObjectLockMode') != 'COMPLIANCE'
                or head.get('ObjectLockRetainUntilDate', datetime.min.replace(tzinfo=timezone.utc)) < self.retention_until):
                raise StorageFailure('stored encryption/version/lock metadata mismatch')
            response = self.client.get_object(Bucket=self.bucket, Key=key, VersionId=version)
            if response.get('VersionId') != version:
                raise StorageFailure('readback exact version mismatch')
            body = response['Body']
            try:
                actual = body.read(len(data)+1)
            finally:
                body.close()
            if sha(actual) != sha(data) or len(actual) != len(data):
                raise StorageFailure('source/readback mismatch')
            return signed(reference, state, self.retention_until.isoformat(), self.key_id, self.signer, sha(canonical({'bucket':self.bucket,'prefix':self.prefix})))
        except StorageFailure:
            raise
        except Exception as exc:
            # Never delete source, abort upload, retry a completed history, or
            # downgrade to non-locking storage on any failure.
            raise StorageFailure('durable sealing failed; quarantine source; retain multipart') from exc

    def _multipart(self, args, data):
        created = self.client.create_multipart_upload(**args, ChecksumAlgorithm='SHA256')
        upload_id = created['UploadId']
        parts = []
        for index, offset in enumerate(range(0, len(data), self.PART_SIZE), 1):
            chunk = data[offset:offset+self.PART_SIZE]
            digest = base64.b64encode(bytes.fromhex(sha(chunk))).decode()
            part = self.client.upload_part(Bucket=self.bucket, Key=args['Key'], UploadId=upload_id,
                PartNumber=index, Body=chunk, ChecksumSHA256=digest)
            if part.get('ChecksumSHA256') != digest or not part.get('ETag'):
                raise StorageFailure('multipart chunk checksum mismatch; retain upload')
            parts.append({'PartNumber':index,'ETag':part['ETag'],'ChecksumSHA256':digest})
        return self.client.complete_multipart_upload(Bucket=self.bucket, Key=args['Key'], UploadId=upload_id,
            MultipartUpload={'Parts':parts}, IfNoneMatch='*')

class S3EvidenceReader:
    """Reviewer capability: get pinned versions only; no write/delete/lookup-latest."""
    def __init__(self, client, *, bucket, authority_sha256, attempt_id, trusted_key, trusted_key_id):
        from .evidence import HEX
        if not HEX.fullmatch(authority_sha256) or not attempt_id.isalnum():
            raise StorageFailure('unapproved namespace')
        self.client, self.bucket = client, bucket
        self.prefix = authority_sha256 + '/' + attempt_id + '/'
        self.key, self.key_id = trusted_key, trusted_key_id

    def read(self, envelope: SealedEvidence, *, require_complete=True):
        envelope.verify(self.key, self.key_id)
        if envelope.storage_scope_sha256 != sha(canonical({'bucket':self.bucket,'prefix':self.prefix})):
            raise StorageFailure('signed campaign/attempt namespace mismatch')
        if require_complete and envelope.state != 'SEALED_COMPLETE':
            raise StorageFailure('partial evidence cannot qualify complete audit')
        reference = envelope.reference
        try:
            result = self.client.get_object(Bucket=self.bucket, Key=self.prefix+reference.object_id, VersionId=reference.version_id)
            if result.get('VersionId') != reference.version_id:
                raise StorageFailure('version mismatch')
            body = result['Body']
            try:
                data = body.read(reference.size_bytes+1)
            finally:
                body.close()
            if len(data) != reference.size_bytes or sha(data) != reference.sha256:
                raise StorageFailure('reviewer readback hash/size mismatch')
            return data
        except StorageFailure:
            raise
        except Exception as exc:
            raise StorageFailure('reviewer cannot retrieve exact private bytes') from exc
