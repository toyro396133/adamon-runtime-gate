"""Strict S3 multipart binding layered over the existing versioned adapter.

Injected SDK only; this module never provisions resources, loads credentials or
performs live I/O at import. Contract-fake tests do not establish AWS acceptance.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
from .evidence import StorageFailure, sha
from .s3 import S3EvidenceWriter


def checksum(data):
    return base64.b64encode(bytes.fromhex(sha(data))).decode('ascii')


SDK_REQUIRED = {
    'PutObject': {'IfNoneMatch','ChecksumSHA256','ServerSideEncryption','SSEKMSKeyId',
                  'SSEKMSEncryptionContext','ObjectLockMode','ObjectLockRetainUntilDate'},
    'CreateMultipartUpload': {'ChecksumAlgorithm','ChecksumType','ServerSideEncryption',
                             'SSEKMSKeyId','SSEKMSEncryptionContext','ObjectLockMode','ObjectLockRetainUntilDate'},
    'UploadPart': {'PartNumber','UploadId','ChecksumSHA256','Body'},
    'CompleteMultipartUpload': {'IfNoneMatch','ChecksumSHA256','ChecksumType','MpuObjectSize','MultipartUpload','UploadId'},
    'HeadObject': {'VersionId'},
    'GetObject': {'VersionId'},
}


def verify_s3_sdk_contract(client):
    """Reject SDKs incapable of conditional full multipart binding, no downgrade.

    The actual installed botocore model is examined, rather than relying on an
    unverified package-version assertion. The owner build must also pin wheels.
    A synthetic model in tests is explicitly a contract emulator.
    """
    try:
        model=client.meta.service_model
        if model.service_name!='s3':raise ValueError('not S3')
        for name,required in SDK_REQUIRED.items():
            operation=model.operation_model(name)
            if not required <= set(operation.input_shape.members):
                raise ValueError('unsupported API shape')
        complete=model.operation_model('CompleteMultipartUpload')
        if 'COMPOSITE' not in complete.input_shape.members['ChecksumType'].enum:
            raise ValueError('unsupported multipart checksum mode')
    except Exception as exc:
        raise StorageFailure('installed S3 SDK conditional/checksum/VersionId contract unavailable') from exc
    return dict(status='SDK_MODEL_VALIDATED_NOT_AWS_VERIFIED',operations=sorted(SDK_REQUIRED))


@dataclass(frozen=True)
class MultipartPlan:
    size_bytes: int
    sha256: str
    parts: tuple
    composite_sha256: str

    @classmethod
    def create(cls, data, part_size=32*1024*1024):
        if type(data) is not bytes or not data:
            raise StorageFailure('nonempty original multipart bytes required')
        if type(part_size) is not int or not 5*1024*1024 <= part_size <= 5*1024*1024*1024:
            raise StorageFailure('S3 multipart part size outside permitted range')
        count = (len(data)+part_size-1)//part_size
        if not 1 <= count <= 10000 or len(data) > 5*1024**4:
            raise StorageFailure('multipart object exceeds fixed S3 bounds')
        parts = tuple((index,offset,min(part_size,len(data)-offset),checksum(data[offset:offset+part_size]))
                      for index,offset in enumerate(range(0,len(data),part_size),1))
        digest = checksum(b''.join(base64.b64decode(p[3],validate=True) for p in parts))+'-'+str(count)
        return cls(len(data),sha(data),parts,digest)


class ProtectedS3EvidenceWriter(S3EvidenceWriter):
    """Fail-closed conditional multipart commit and independently pinned readback.

    Every operation rechecks read-only bucket controls. AWS authorization and race
    denial still require live PF-07. Incomplete uploads are deliberately retained;
    owner cleanup after retention/quarantine is outside producer permissions.
    """
    def __init__(self, client, *, configuration_client=None, **kwargs):
        super().__init__(client,**kwargs)
        self.configuration_client=configuration_client or client
        self.sdk_contract=verify_s3_sdk_contract(client)

    def verify_configuration(self):
        # Configuration inspection is a separately injectable owner read-only
        # capability. Do not grant bucket-policy access to producer/reviewer.
        probe=object.__new__(S3EvidenceWriter)
        probe.client,probe.bucket,probe.kms=self.configuration_client,self.bucket,self.kms
        probe.preflight_passed=False
        self.preflight_passed=False
        result=probe.verify_configuration()
        self.preflight_passed=True
        return result

    def put(self, data, state='SEALED_COMPLETE'):
        if type(data) is not bytes or not data:
            raise StorageFailure('nonempty immutable original bytes required')
        self.verify_configuration()
        return super().put(data,state)

    def _multipart(self, args, data):
        plan = MultipartPlan.create(data,self.PART_SIZE)
        created = self.client.create_multipart_upload(**args,ChecksumAlgorithm='SHA256',ChecksumType='COMPOSITE')
        upload_id = created.get('UploadId')
        if type(upload_id) is not str or not upload_id or len(upload_id)>2048:
            raise StorageFailure('exact retained multipart upload identity required')
        parts = []
        for number,offset,size,expected in plan.parts:
            body = data[offset:offset+size]
            if len(body)!=size or checksum(body)!=expected:
                raise StorageFailure('original multipart plan mismatch')
            result = self.client.upload_part(Bucket=self.bucket,Key=args['Key'],UploadId=upload_id,
                PartNumber=number,Body=body,ChecksumSHA256=expected)
            if (result.get('ChecksumSHA256')!=expected or type(result.get('ETag')) is not str
                or not result['ETag'] or result.get('ChecksumType','COMPOSITE')!='COMPOSITE'):
                raise StorageFailure('multipart authenticated part mismatch; retain upload')
            parts.append(dict(PartNumber=number,ETag=result['ETag'],ChecksumSHA256=expected))
        result = self.client.complete_multipart_upload(Bucket=self.bucket,Key=args['Key'],UploadId=upload_id,
            MultipartUpload={'Parts':parts},IfNoneMatch='*',ChecksumSHA256=plan.composite_sha256,
            ChecksumType='COMPOSITE',MpuObjectSize=plan.size_bytes)
        if (result.get('ChecksumSHA256')!=plan.composite_sha256
            or result.get('ChecksumType')!='COMPOSITE'):
            raise StorageFailure('multipart completion checksum/truncation mismatch; preserve source')
        # Superclass verifies exact VersionId, byte length, KMS/COMPLIANCE metadata
        # and re-downloads full pinned bytes. ETags never stand in for SHA256.
        return result
