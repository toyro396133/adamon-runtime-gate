"""S3 SDK contract emulator: multipart correctness, never AWS service proof."""
import base64
import copy
import io
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.tests.test_storage import FakeS3
from infrastructure.t3.storage.s3 import S3EvidenceReader
from infrastructure.t3.storage.s3_protected import ProtectedS3EvidenceWriter,MultipartPlan,checksum,SDK_REQUIRED,verify_s3_sdk_contract
from infrastructure.t3.storage.evidence import StorageFailure
from infrastructure.t3.storage.policies import protected_storage_policies


class MultipartS3(FakeS3):
    def __init__(self):
        super().__init__();self.kms='arn:aws:kms:us-east-1:123456789012:key/synthetic';self.truncate=False
        from types import SimpleNamespace
        class Model:
            service_name='s3'
            def operation_model(_,name):
                return SimpleNamespace(input_shape=SimpleNamespace(members={k:SimpleNamespace(enum=['COMPOSITE']) for k in SDK_REQUIRED[name]}))
        self.meta=SimpleNamespace(service_model=Model())
        self.completion_checksum=False;self.wrong_head_version=False;self.wrong_head_kms=False
        self.fail_completion=False;self.missing=False;self.partial_failure=False
    def complete_multipart_upload(self,**kw):
        self.calls.append(('complete',kw))
        if self.fail_completion:raise RuntimeError('conditional conflict')
        assert kw['IfNoneMatch']=='*' and kw['ChecksumType']=='COMPOSITE'
        data=b''.join(self.parts[p['PartNumber']] for p in kw['MultipartUpload']['Parts'])
        if self.truncate:data=data[:-1]
        result=self.put_object(**self.multipart_args,Body=data,IfNoneMatch=kw['IfNoneMatch'])
        result.update(ChecksumSHA256='forged' if self.completion_checksum else kw['ChecksumSHA256'],ChecksumType='COMPOSITE')
        return result
    def upload_part(self,**kw):
        if self.partial_failure and kw['PartNumber']==2:raise RuntimeError('network outage')
        return super().upload_part(**kw)
    def head_object(self,**kw):
        if self.missing:raise RuntimeError('missing object')
        result=super().head_object(**kw)
        if self.wrong_head_version:result['VersionId']='foreign'
        if self.wrong_head_kms:result['SSEKMSKeyId']='arn:aws:kms:us-east-1:123456789012:key/foreign'
        return result


def setup():
    c=MultipartS3();key=Ed25519PrivateKey.generate()
    writer=ProtectedS3EvidenceWriter(c,bucket='private-evidence',kms_key_arn=c.kms,authority_sha256='a'*64,
        attempt_id='attempt1',signer=key,signer_key_id='broker')
    writer.PART_SIZE=5*1024*1024
    reader=S3EvidenceReader(c,bucket='private-evidence',kms_key_arn=c.kms,authority_sha256='a'*64,
        attempt_id='attempt1',trusted_key=key.public_key(),trusted_key_id='broker')
    return c,writer,reader


def test_multipart_full_original_plan_and_exact_version_readback():
    c,w,r=setup();data=b'a'*(w.PART_SIZE+17);receipt=w.put(data)
    assert r.read(receipt)==data
    complete=next(x[1] for x in c.calls if x[0]=='complete');plan=MultipartPlan.create(data,w.PART_SIZE)
    assert complete['MpuObjectSize']==len(data) and complete['ChecksumSHA256']==plan.composite_sha256
    assert complete['IfNoneMatch']=='*' and len(complete['MultipartUpload']['Parts'])==2
    assert all(x[1]['VersionId']=='pinned-version' for x in c.calls if x[0]=='get')
    assert complete['ChecksumSHA256']!=checksum(data) # SHA256 COMPOSITE != full-object SHA256.


@pytest.mark.parametrize('mutation,message',[
    ('truncate','metadata'),('completion_checksum','checksum'),('part_corrupt','part'),
    ('wrong_head_version','metadata'),('wrong_head_kms','metadata'),('corrupt','readback'),
    ('fail_completion','quarantine'),('partial_failure','quarantine')])
def test_single_multipart_failure_retains_bytes_and_never_downgrades(mutation,message):
    c,w,r=setup();data=b'a'*(w.PART_SIZE+17)
    # Same control state succeeds before the one isolated mutation.
    c0,w0,r0=setup();assert r0.read(w0.put(data))==data
    setattr(c,mutation,True)
    with pytest.raises(StorageFailure,match=message):w.put(data)
    assert c.parts[1]==data[:w.PART_SIZE]
    assert not any(name in {'delete','abort'} for name,args in c.calls)


def test_conditional_duplicate_and_changed_configuration_rejected():
    c,w,r=setup();receipt=w.put(b'original')
    with pytest.raises(StorageFailure):w.put(b'original')
    assert r.read(receipt)==b'original'
    c.mode='GOVERNANCE'
    before=len(c.data)
    with pytest.raises(StorageFailure,match='compliance'):w.put(b'fresh')
    assert len(c.data)==before


def test_missing_version_wrong_kms_and_modified_reader_bytes():
    c,w,r=setup();receipt=w.put(b'original')
    assert r.read(receipt)==b'original'
    for field in ('missing','wrong_head_version','wrong_head_kms','corrupt'):
        setattr(c,field,True)
        with pytest.raises(StorageFailure):r.read(receipt)
        setattr(c,field,False)
        assert r.read(receipt)==b'original'


def test_multipart_minimum_and_count_closed():
    with pytest.raises(StorageFailure,match='part size'):MultipartPlan.create(b'bytes',5)
    with pytest.raises(StorageFailure):MultipartPlan.create(b'',5*1024*1024)


def test_scoped_policy_roles_no_latest_no_delete_no_cloud_provisioning():
    p=protected_storage_policies(bucket='private-evidence',kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/synthetic',
        authority_sha256='a'*64,attempt_id='attempt1',region='us-east-1')
    assert p['scope']=='OWNER_REVIEW_TEMPLATE_NOT_EFFECTIVE_IAM_PROOF'
    assert p['required_bucket']['bucket_key_enabled'] is False
    for role in ('producer','auditor','reviewer'):
        allowed={a for row in p[role]['Statement'] if row['Effect']=='Allow' for a in row['Action']}
        assert not allowed.intersection({'s3:DeleteObject','s3:DeleteObjectVersion','s3:CreateBucket','s3:GetObject'})
        assert 's3:GetObjectVersion' in allowed
        assert 'kms:Decrypt' in allowed
        if role!='producer':assert 's3:PutObject' not in allowed and 'kms:GenerateDataKey' not in allowed
    conditional=p['bucket_policy']['Statement'][1]
    assert conditional['Condition']=={'Null':{'s3:if-none-match':'true'},'Bool':{'s3:ObjectCreationOperation':'true'}}
    producer_allow=next(row for row in p['producer']['Statement'] if row['Sid']=='CreateBrokerBytes')
    assert 'Condition' not in producer_allow # CompleteMultipartUpload has no SSE/lock request headers.
    assert p['auditor']==p['reviewer']


@pytest.mark.parametrize('field,value',[('bucket','*'),('attempt_id','../'),('kms_key_arn','arn:aws:kms:*:*:key/*'),('region','eu-west-1')])
def test_policy_no_wildcard_or_cross_region_scope(field,value):
    args=dict(bucket='private-evidence',kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/synthetic',authority_sha256='a'*64,attempt_id='attempt1',region='us-east-1')
    args[field]=value
    with pytest.raises(StorageFailure):protected_storage_policies(**args)


def test_configuration_reader_is_separate_from_producer_permissions():
    c,w,r=setup()
    class ConfigurationOnly:
        def __getattr__(self,name):
            if name not in {'get_bucket_versioning','get_public_access_block','get_object_lock_configuration','get_bucket_encryption','get_bucket_policy'}:
                raise AssertionError('configuration reader cannot perform byte operations')
            return getattr(c,name)
    class ProducerOnly:
        def __getattr__(self,name):
            if name in {'get_bucket_versioning','get_public_access_block','get_object_lock_configuration','get_bucket_encryption','get_bucket_policy'}:
                raise AssertionError('producer must not need bucket configuration permission')
            return getattr(c,name)
    w.client=ProducerOnly();w.configuration_client=ConfigurationOnly()
    assert r.read(w.put(b'original'))==b'original'


def test_kms_policy_binds_custom_authority_and_attempt_context():
    p=protected_storage_policies(bucket='private-evidence',kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/synthetic',
        authority_sha256='a'*64,attempt_id='attempt1',region='us-east-1')
    row=next(x for x in p['reviewer']['Statement'] if x['Sid']=='ScopedKmsDecrypt')
    assert row['Condition']['StringEquals']['kms:EncryptionContext:authority']=='a'*64
    assert row['Condition']['StringEquals']['kms:EncryptionContext:attempt']=='attempt1'
    p['auditor']['Statement'][0]['Sid']='mutated-template'
    assert p['reviewer']['Statement'][0]['Sid']=='NoDestructiveOrConfigurationAuthority'



def test_unsupported_sdk_fails_before_any_cloud_operation():
    from types import SimpleNamespace
    c,w,r=setup()
    class OldModel:
        service_name='s3'
        def operation_model(self,name):
            members={k:SimpleNamespace(enum=['COMPOSITE']) for k in SDK_REQUIRED[name]}
            members.pop('IfNoneMatch',None)
            return SimpleNamespace(input_shape=SimpleNamespace(members=members))
    c.meta.service_model=OldModel()
    with pytest.raises(StorageFailure,match='SDK'):verify_s3_sdk_contract(c)
    with pytest.raises(StorageFailure,match='SDK'):
        ProtectedS3EvidenceWriter(c,bucket='private-evidence',kms_key_arn=c.kms,authority_sha256='a'*64,
            attempt_id='attempt1',signer=Ed25519PrivateKey.generate(),signer_key_id='broker')
    assert c.calls==[]
