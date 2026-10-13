"""Closed least-privilege policy generator; no deployment or credential loading.

Policies are reviewable owner inputs, not proof that effective IAM grants match.
Producer is the trusted byte broker, never guest/LIFE. Auditor and reviewer receive
separate roles with exact GetObjectVersion and KMS Decrypt, no latest/write/delete.
No role can create buckets, alter retention, change keys or manage grants.
"""
import re
from .evidence import StorageFailure, HEX

BUCKET = re.compile(r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')
KMS = re.compile(r'^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$')


def protected_storage_policies(*, bucket, kms_key_arn, authority_sha256, attempt_id, region):
    if (type(bucket) is not str or not BUCKET.fullmatch(bucket) or '..' in bucket
        or type(kms_key_arn) is not str or not KMS.fullmatch(kms_key_arn)
        or kms_key_arn.split(':')[3]!=region
        or type(authority_sha256) is not str or not HEX.fullmatch(authority_sha256)
        or type(attempt_id) is not str or not attempt_id.isalnum() or len(attempt_id)>64):
        raise StorageFailure('literal private bucket/key/region/attempt policy scope required')
    bucket_arn='arn:aws:s3:::'+bucket
    objects=bucket_arn+'/'+authority_sha256+'/'+attempt_id+'/*'
    # ARN context uses StringLike to permit only this prefix; literal authority and
    # attempt contain no wildcards. No context unrelated to this S3 scope is allowed.
    context={'StringEquals':{'kms:ViaService':'s3.'+region+'.amazonaws.com',
                            'kms:EncryptionContext:authority':authority_sha256,
                            'kms:EncryptionContext:attempt':attempt_id},
             'StringLike':{'kms:EncryptionContext:aws:s3:arn':objects}}
    forbidden=['s3:DeleteObject','s3:DeleteObjectVersion','s3:BypassGovernanceRetention',
        's3:PutObjectRetention','s3:PutObjectLegalHold','s3:PutObjectAcl',
        's3:PutBucketVersioning','s3:PutBucketObjectLockConfiguration',
        's3:PutBucketPolicy','s3:DeleteBucketPolicy','s3:PutEncryptionConfiguration']
    shared=[dict(Sid='NoDestructiveOrConfigurationAuthority',Effect='Deny',Action=forbidden,
                 Resource=[bucket_arn,objects])]
    def document(statements):return {'Version':'2012-10-17','Statement':shared+statements}
    get=dict(Sid='ExactVersionReadOnly',Effect='Allow',Action=['s3:GetObjectVersion','s3:GetObjectVersionAttributes'],Resource=objects)
    decrypt=dict(Sid='ScopedKmsDecrypt',Effect='Allow',Action=['kms:Decrypt'],Resource=kms_key_arn,Condition=context)
    reviewer=document([get,decrypt,dict(Sid='NoMutationOrLatest',Effect='Deny',
        Action=['s3:PutObject','s3:AbortMultipartUpload','s3:GetObject','s3:ListBucket'],Resource=[bucket_arn,objects])])
    producer=document([dict(Sid='CreateBrokerBytes',Effect='Allow',Action=['s3:PutObject'],Resource=objects),
        get,decrypt,
        dict(Sid='ScopedKmsDataKey',Effect='Allow',Action=['kms:GenerateDataKey'],Resource=kms_key_arn,Condition=context),
        dict(Sid='NeverDiscardIncompleteUpload',Effect='Deny',Action=['s3:AbortMultipartUpload'],Resource=objects),
        dict(Sid='DenyExplicitWrongEncryption',Effect='Deny',Action=['s3:PutObject'],Resource=objects,
            Condition={'Null':{'s3:x-amz-server-side-encryption':'false'},
                'StringNotEquals':{'s3:x-amz-server-side-encryption':'aws:kms'}}),
        dict(Sid='DenyExplicitWrongKey',Effect='Deny',Action=['s3:PutObject'],Resource=objects,
            Condition={'Null':{'s3:x-amz-server-side-encryption-aws-kms-key-id':'false'},
                'StringNotEquals':{'s3:x-amz-server-side-encryption-aws-kms-key-id':kms_key_arn}}),
        dict(Sid='DenyExplicitWrongLock',Effect='Deny',Action=['s3:PutObject'],Resource=objects,
            Condition={'Null':{'s3:object-lock-mode':'false'},
                'StringNotEquals':{'s3:object-lock-mode':'COMPLIANCE'}}),
        dict(Sid='DenyExplicitShortRetention',Effect='Deny',Action=['s3:PutObject'],Resource=objects,
            Condition={'Null':{'s3:object-lock-remaining-retention-days':'false'},
                'NumericLessThan':{'s3:object-lock-remaining-retention-days':'365'}})])
    bucket_policy={'Version':'2012-10-17','Statement':[
        dict(Sid='RequireTls',Effect='Deny',Principal='*',Action='s3:*',Resource=[bucket_arn,bucket_arn+'/*'],Condition={'Bool':{'aws:SecureTransport':'false'}}),
        dict(Sid='RequireConditionalCreate',Effect='Deny',Principal='*',Action='s3:PutObject',Resource=objects,
            Condition={'Null':{'s3:if-none-match':'true'},'Bool':{'s3:ObjectCreationOperation':'true'}})]}
    configuration_reader={'Version':'2012-10-17','Statement':[
        dict(Sid='OwnerReadonlyConfiguration',Effect='Allow',
            Action=['s3:GetBucketVersioning','s3:GetBucketPublicAccessBlock',
                's3:GetBucketObjectLockConfiguration','s3:GetEncryptionConfiguration','s3:GetBucketPolicy'],
            Resource=bucket_arn)]}
    import copy
    return dict(version=1,configuration_reader=configuration_reader,scope='OWNER_REVIEW_TEMPLATE_NOT_EFFECTIVE_IAM_PROOF',
        producer=producer,auditor=copy.deepcopy(reviewer),reviewer=reviewer,bucket_policy=bucket_policy,
        required_bucket=dict(versioning='Enabled',encryption='aws:kms',kms_key_arn=kms_key_arn,
            object_lock='COMPLIANCE',retention_days=365,public_access_block=True,bucket_key_enabled=False),
        live_checks=['conditional-single-and-multipart-race','exact-version-readback',
            'deny-latest','deny-cross-prefix','deny-wrong-kms-context','deny-delete-and-retention-shortening'])


def main(argv=None):
    """Pure static owner CLI. Produces JSON templates; performs no AWS operation."""
    import argparse
    import json
    from pathlib import Path
    from .evidence import canonical
    parser=argparse.ArgumentParser(description='Generate owner-review policy JSON without provisioning')
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    config=json.loads(args.config.read_bytes())
    if type(config) is not dict or set(config)!={'bucket','kms_key_arn','authority_sha256','attempt_id','region'}:
        raise StorageFailure('closed static policy configuration required')
    result=protected_storage_policies(**config)
    with args.output.open('xb') as stream:
        stream.write(canonical(result)+b'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
