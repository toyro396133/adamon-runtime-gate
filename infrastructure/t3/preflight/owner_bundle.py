"""One PF-00..09 owner handoff, not authorization, provisioning or execution.

Produces a closed machine-readable activation package with the existing gates.
Only owner-installed paths below are used in command examples; they are not RPC
inputs, installed workflows or executable instructions issued by this program.
"""
import argparse
import hashlib
import json
from pathlib import Path
from .sequence import GATES, SHA, HEX, canonical

FIELDS={'version','private_commit','public_commit','authority_sha256','source_fingerprints','mke2fs_sha256'}
OWNER_BASE='/owner/adamon'


def create(context):
    if type(context) is not dict or set(context)!=FIELDS or type(context['version']) is not int or context['version']!=1:
        raise ValueError('closed owner handoff context required')
    for field in ('private_commit','public_commit'):
        if type(context[field]) is not str or not SHA.fullmatch(context[field]):
            raise ValueError('exact candidate commit required')
    if type(context['authority_sha256']) is not str or not HEX.fullmatch(context['authority_sha256']):
        raise ValueError('exact authority digest required')
    if type(context['mke2fs_sha256']) is not str or not HEX.fullmatch(context['mke2fs_sha256']):
        raise ValueError('exact owner build tool digest required')
    fingerprints=context['source_fingerprints']
    if type(fingerprints) is not dict or set(fingerprints)!={'private','public'}:
        raise ValueError('both exact source fingerprint maps required')
    for files in fingerprints.values():
        if type(files) is not dict or not files:raise ValueError('empty source fingerprint map')
        for name,value in files.items():
            if type(name) is not str:raise ValueError('closed source fingerprint entry required')
            path=Path(name)
            if (type(name) is not str or not name.startswith('infrastructure/t3/')
                or path.is_absolute() or '..' in path.parts
                or type(value) is not str or not HEX.fullmatch(value)):
                raise ValueError('closed source fingerprint entry required')
    gates=[]
    for gate,(role,kind,requirements) in GATES.items():
        gates.append(dict(gate=gate,signer_role=role,required_proof_kind=kind,
            requirements=list(requirements),status='BLOCKED_OWNER_APPROVAL',
            receipt_protocol='ADAMON-PREFLIGHT-V1',is_authorization=False))
    commands=[
        dict(name='runner_bundle',gate='PF-01',scope='OWNER_BUILD_INPUT_ONLY',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.runner.build_bundle',
                '--checkout',OWNER_BASE+'/runner','--sdk',OWNER_BASE+'/sdk/dotnet',
                '--feed',OWNER_BASE+'/frozen-nupkg-feed']),
        dict(name='source_bundle',gate='PF-04',scope='OWNER_BUILD_INPUT_ONLY',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.deployment.build_bundle',
                '--expected-manifest',OWNER_BASE+'/source-manifest.json','--output',OWNER_BASE+'/source-input.zip']),
        dict(name='nonresearch_rootfs',gate='PF-04',scope='OWNER_BUILD_ONLY_NO_BOOT',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.deployment.rootfs_build',
                '--base',OWNER_BASE+'/pinned-base','--base-manifest',OWNER_BASE+'/base-manifest.json',
                '--source-manifest',OWNER_BASE+'/source-manifest.json',
                '--owner-public-key',OWNER_BASE+'/canary-owner-public-key',
                '--staging',OWNER_BASE+'/new-rootfs-tree','--output',OWNER_BASE+'/new-rootfs.ext4',
                '--mke2fs',OWNER_BASE+'/tools/mke2fs',
                '--mke2fs-sha256',context['mke2fs_sha256']]),
        dict(name='read_only_host_observation',gate='PF-02',scope='OBSERVATION_NOT_LIVE_PROOF',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.preflight.check','--probe']),
        dict(name='storage_policy_templates',gate='PF-07',scope='OWNER_REVIEW_NO_AWS_OPERATION',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.storage.policies',
                '--config',OWNER_BASE+'/storage-config.json','--output',OWNER_BASE+'/storage-policy.json']),
        dict(name='verify_signed_proof_package',gate='PF-09',scope='OFFLINE_PROOF_VERIFICATION_ONLY',
            cwd=OWNER_BASE+'/public',argv=['python','-m','infrastructure.t3.preflight.sequence',
                '--policy',OWNER_BASE+'/owner-installed-policy.json',
                '--receipts',OWNER_BASE+'/signed-pf-receipts.json',
                '--artifacts',OWNER_BASE+'/protected-proof-artifacts'])]
    return dict(version=1,kind='UNIFIED_OWNER_PREFLIGHT_HANDOFF',context=context,
        context_sha256=hashlib.sha256(canonical(context)).hexdigest(),gates=gates,commands=commands,
        owner_only_runtime_api='infrastructure.t3.deployment.service.OwnerDeploymentService',
        runtime_constraints=dict(nonresearch_subject='NONRESEARCH_SOCKET_CANARY',
            repository='toyro396133/adamon-runtime-gate',all_scientific_compute_inside_actions_job=True,
            workflow_installation_authorized=False,live_dispatch_authorized=False,
            provision_authorized=False,research_authorized=False,terminal_pass_signing_authorized=False),
        minimum_host=dict(logical_cpus=8,memory_bytes=32*1024**3,
            encrypted_disk_bytes=1024**4,free_disk_bytes=512*1024**3,
            capabilities=['KVM','cgroup_v2','pidfd','clone3','execveat','mount_namespace',
                          'network_namespace','UID_GID_separation','seccomp_LSM']),
        owner_actions=['approve PF-00 scope and spending once',
            'provide pinned toolchain/image/base/SDK bytes and freeze transitive packages',
            'authorize existing PF-00..09 nonresearch tests on a single suitable host',
            'authorize separate dedicated synthetic S3/KMS test bucket with365dayretention',
            'install reviewed exact-SHA public workflow only after separate owner approval',
            'retain private proof originals and provide separate reviewer read capability'],
        cost_categories=['owner-approved host compute','encrypted disk capacity',
            'S3 retention/storage/request charges','KMS request charges'],
        cost_estimate_status='NO_ACCOUNT_PRICING_AVAILABLE_NO_AMOUNT_CLAIMED',
        retention=dict(minimum_days=365,mode='COMPLIANCE',
            protected_originals_cleanup='NO_DELETE_BEFORE_RETENTION_EXPIRY',
            temporary_cleanup='terminate owned cgroups/pidfds; revoke credentials; preserve signed PARTIAL before removing temporary mounts'),
        live_proof_required=['actual approved GitHub Job','full Listener/Worker build',
            'real namespaces/cgroup/KVM','failure/cancellation and descendants',
            'exact-version encrypted ObjectLock readback','independent reviewer inspection'],
        status='OWNER_APPROVAL_AND_EXTERNAL_PROOF_REQUIRED',execution_authorized=False,
        is_execution_freeze=False,independent_acceptance=False,research_executed=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv)
    from .sequence import load_json
    value=create(load_json(args.context))
    with args.output.open('xb') as stream:stream.write(canonical(value)+b'\n')
    print(json.dumps({'status':value['status'],'sha256':hashlib.sha256(canonical(value)+b'\n').hexdigest(),
                      'execution_authorized':False},sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
