"""Closed, offline PF-00..09 receipt verifier. Never dispatches or provisions.

Trust policy must be installed by the owner/reviewer, outside a workflow's
writable workspace. A signed attestation is attributed evidence, not an
independent observation that an implementation/runtime claim is true.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from infrastructure.t3.preflight.check import inspect_host

GATES = {
 'PF-00': ('owner', 'OWNER_AUTHORIZATION', ('nonresearch_only','spending_scope','host_scope','secret_scope','data_scope')),
 'PF-01': ('builder', 'COMPLETE_RUNNER_BUILD', ('upstream_pin','patch_pin','dependency_lock','complete_listener_worker_build','build_outputs','security_update_policy')),
 'PF-02': ('owner', 'LIVE_RUNTIME', ('cpu_8','memory_32_gib','encrypted_disk_1_tib','free_disk_512_gib','kvm_usable','cgroup_v2','pidfd','kernel_namespaces_lsm','host_image')),
 'PF-03': ('runtime', 'LIVE_RUNTIME', ('actual_actions_job','legacy_broker_identity','workflow_ref_sha_job','unauthorized_rejected_before_code','no_private_bytes')),
 'PF-04': ('runtime', 'LIVE_RUNTIME', ('uid_separation','clone3_pidfd_execveat','cgroup_kill','network_mount_namespaces','pinned_firecracker_kernel_rootfs_launcher_guest','readonly_source_mounts','evidence_volume_scope')),
 'PF-05': ('security', 'LIVE_RUNTIME', ('ed25519_mtls_spki_challenge','accepted_socket_peercred','atomic_ledger','replay_race_expiry_revoke_crash','process_death_cleanup','no_research_permit')),
 'PF-06': ('runtime', 'LIVE_RUNTIME', ('cancel_timeout_stale_lease','github_api_outage','supervisor_worker_launcher_death','all_vmm_descendants_killed','signed_partial_retained','no_semantic_pass')),
 'PF-07': ('storage', 'LIVE_RUNTIME', ('versioned_s3','object_lock_compliance_365_days','kms_exact_scope','conditional_multipart_races','signed_sha_versionid','exact_readback','reviewer_least_privilege','reviewer_independent_byte_verification')),
 'PF-08': ('security', 'LIVE_RUNTIME', ('canary_all_public_logs','setup_failure_cleanup_logs','no_private_code_tokens_db_keys','no_public_artifact_leak')),
 'PF-09': ('reviewer', 'INDEPENDENT_REVIEW', ('frozen_inputs_verified','exact_images_build_environment_workflow_scopes','counts_27_23_2_12','micro_authority_resolved','all_prior_gates_verified','no_execution_freeze')),
}
HEX = re.compile(r'^[0-9a-f]{64}$')
SHA = re.compile(r'^[0-9a-f]{40}$')
CONTEXT_FIELDS = {'campaign_id','private_commit','public_commit','authority_sha256','policy_sha256'}
RECEIPT_FIELDS = {'version','gate','kind','signer','issued_at','expires_at','context','owner_authorization_sha256','job','requirements','artifacts','status'}
POLICY_FIELDS = {'version','context','keys','maximum_receipt_age_seconds','approved_job'}
JOB_FIELDS = {'repository','workflow_ref','workflow_sha','run_id','run_attempt','job_id'}

class Rejected(ValueError): pass

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def _closed(value, fields):
    if type(value) is not dict or set(value) != fields: raise Rejected('closed schema mismatch')

def _date(value):
    if type(value) is not str or not value.endswith('Z'): raise Rejected('UTC timestamp required')
    try: return datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError as exc: raise Rejected('invalid timestamp') from exc

def _hex(value):
    if type(value) is not str or not HEX.fullmatch(value): raise Rejected('SHA256 required')

def load_json(path):
    def unique(items):
        result={}
        for key,value in items:
            if key in result: raise Rejected('duplicate JSON key')
            result[key]=value
        return result
    with Path(path).open('rb') as stream: data=stream.read(4*1024*1024+1)
    if len(data)>4*1024*1024: raise Rejected('document exceeds limit')
    return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite number')))

def validate_policy(policy):
    _closed(policy,POLICY_FIELDS)
    if type(policy['version']) is not int or policy['version']!=1: raise Rejected('policy version')
    context=policy['context']; _closed(context,CONTEXT_FIELDS-{'policy_sha256'})
    for field in ('private_commit','public_commit'):
        if type(context[field]) is not str or not SHA.fullmatch(context[field]): raise Rejected('exact Git commit required')
    _hex(context['authority_sha256'])
    if type(context['campaign_id']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',context['campaign_id']): raise Rejected('campaign id')
    maximum=policy['maximum_receipt_age_seconds']
    if type(maximum) is not int or not 1<=maximum<=86400*30: raise Rejected('receipt age policy')
    if type(policy['keys']) is not dict or not policy['keys']: raise Rejected('trusted signer keys missing')
    owner_keys=set(); reviewer_keys=set()
    for name,key in policy['keys'].items():
        if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name): raise Rejected('key identity')
        _closed(key,{'role','public_key_hex'})
        if type(key['role']) is not str or key['role'] not in {r[0] for r in GATES.values()}: raise Rejected('unknown signer role')
        _hex(key['public_key_hex'])
        for other_name,other_key in policy['keys'].items():
            if other_name!=name and type(other_key) is dict and other_key.get('public_key_hex')==key['public_key_hex'] and other_key.get('role')!=key['role']: raise Rejected('cross-role key reuse')
        if key['role']=='owner': owner_keys.add(key['public_key_hex'])
        if key['role']=='reviewer': reviewer_keys.add(key['public_key_hex'])
    if not owner_keys or not reviewer_keys or owner_keys & reviewer_keys: raise Rejected('independent owner/reviewer keys required')
    if policy['approved_job'] is not None:
        _closed(policy['approved_job'],JOB_FIELDS)
        canonical(policy['approved_job'])
    return {**context,'policy_sha256':digest(policy)}

def verify_receipt(envelope, gate, policy, context, now, owner_hash, artifact_root):
    _closed(envelope,{'payload','signature_hex'})
    payload=envelope['payload']; _closed(payload,RECEIPT_FIELDS)
    if type(payload['version']) is not int or payload['version']!=1: raise Rejected('receipt version')
    role,kind,requirements=GATES[gate]
    if payload['gate']!=gate or payload['kind']!=kind: raise Rejected('wrong gate or proof classification')
    _closed(payload['context'],CONTEXT_FIELDS)
    if canonical(payload['context'])!=canonical(context): raise Rejected('source/policy/authority context mismatch')
    if type(payload['signer']) is not str: raise Rejected('signer identity')
    signer=policy['keys'].get(payload['signer'])
    if not signer or signer['role']!=role: raise Rejected('wrong signer role')
    signature=envelope['signature_hex']
    if type(signature) is not str or not re.fullmatch('[0-9a-f]{128}',signature): raise Rejected('signature encoding')
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer['public_key_hex'])).verify(bytes.fromhex(signature),b'ADAMON-PREFLIGHT-V1\n'+canonical(payload))
    except (InvalidSignature,ValueError) as exc: raise Rejected('invalid signature') from exc
    issued=_date(payload['issued_at']); expires=_date(payload['expires_at'])
    if not issued<=now<expires or expires<=issued or (now-issued).total_seconds()>policy['maximum_receipt_age_seconds']: raise Rejected('expired/future receipt')
    if payload['owner_authorization_sha256']!=(None if gate=='PF-00' else owner_hash): raise Rejected('owner authorization binding')
    if gate not in ('PF-00','PF-01','PF-09'):
        _closed(payload['job'],JOB_FIELDS)
        job=payload['job']
        if policy['approved_job'] is None or canonical(job)!=canonical(policy['approved_job']): raise Rejected('Job not bound to owner policy')
        if job['repository']!='toyro396133/adamon-runtime-gate': raise Rejected('wrong Actions repository')
        if not isinstance(job['workflow_ref'],str) or not job['workflow_ref'].startswith('toyro396133/adamon-runtime-gate/.github/workflows/') or '@refs/heads/' not in job['workflow_ref']: raise Rejected('workflow ref')
        if type(job['workflow_sha']) is not str or not SHA.fullmatch(job['workflow_sha']): raise Rejected('workflow SHA')
        for field in ('run_id','run_attempt','job_id'):
            if type(job[field]) is not int or job[field]<1: raise Rejected('job identity integer')
    elif payload['job'] is not None: raise Rejected('unexpected Job identity')
    _closed(payload['requirements'],set(requirements))
    if any(type(v) is not bool for v in payload['requirements'].values()): raise Rejected('requirement must be boolean')
    if payload['status'] not in ('PASS','FAIL','BLOCKED','NOT_RUN'): raise Rejected('unknown result status')
    if payload['status']=='PASS' and not all(payload['requirements'].values()): raise Rejected('missing required proof')
    artifacts=payload['artifacts']
    if type(artifacts) is not list or not artifacts or len(artifacts)>128: raise Rejected('exact proof artifacts missing')
    names=set(); evidenced=set()
    for item in artifacts:
        _closed(item,{'name','sha256','size','requirements'})
        name=item['name']
        if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name) or name in ('.','..') or name in names: raise Rejected('closed artifact name')
        names.add(name); _hex(item['sha256'])
        proofs=item['requirements']
        if type(proofs) is not list or not proofs or any(type(v) is not str for v in proofs) or len(set(proofs))!=len(proofs) or not set(proofs)<=set(requirements): raise Rejected('artifact proof coverage')
        evidenced.update(proofs)
        if type(item['size']) is not int or item['size']<1: raise Rejected('artifact size')
        # No evaluator-selected remote paths or network access. Read exact bytes.
        path=artifact_root/name
        if path.is_symlink() or not path.is_file(): raise Rejected('artifact unavailable or symlink')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode): raise Rejected('artifact must be regular file')
            h=hashlib.sha256(); count=0
            for block in iter(lambda:stream.read(1024*1024),b''): h.update(block); count+=len(block)
            after=os.fstat(stream.fileno())
            current=path.stat(follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=(after.st_dev,after.st_ino): raise Rejected('artifact path substitution')
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or count!=item['size'] or h.hexdigest()!=item['sha256']: raise Rejected('artifact bytes drift/mismatch')
    if payload['status']=='PASS' and evidenced!=set(requirements): raise Rejected('requirement evidence coverage incomplete')
    return {'state':payload['status'],'receipt_sha256':digest(envelope),'proof_kind':kind,'verification':'SIGNATURE_AND_ARTIFACT_BYTES_VERIFIED_NOT_INDEPENDENT_RUNTIME_OBSERVATION','signer_role':role}

def evaluate(policy, receipts, artifact_root, now=None):
    context=validate_policy(policy)
    if type(receipts) is not dict or not set(receipts)<=set(GATES): raise Rejected('unknown/duplicate gate')
    now=now or datetime.now(timezone.utc)
    results={}; owner_hash=None
    for gate in GATES:
        if gate not in receipts:
            results[gate]={'state':'BLOCKED','reason':'signed receipt absent'}; continue
        if gate!='PF-00' and not owner_hash:
            results[gate]={'state':'BLOCKED','reason':'valid owner authorization absent'}; continue
        if gate=='PF-09' and any(v['state']!='PASS' for v in results.values()):
            results[gate]={'state':'BLOCKED','reason':'prior preflight gate incomplete'}; continue
        try:
            result=verify_receipt(receipts[gate],gate,policy,context,now,owner_hash,artifact_root)
            if gate=='PF-00' and result['state']=='PASS': owner_hash=result['receipt_sha256']
            results[gate]=result
        except (Rejected,OSError,TypeError,KeyError) as exc: results[gate]={'state':'FAIL','reason':str(exc)}
    return {'version':1,'kind':'NONRESEARCH_OFFLINE_PREFLIGHT_RECEIPT_VERIFICATION','status':'SIGNED_PREFLIGHT_PACKAGE_COMPLETE_PENDING_OWNER_EXECUTION_DECISION' if all(v['state']=='PASS' for v in results.values()) else 'PREFLIGHT_INCOMPLETE','context':context,'gates':results,'research_executed':False,'execution_authorized':False,'independent_acceptance_performed':False}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',required=True,help='owner-installed trust policy; never trust an attacker-provided policy')
    parser.add_argument('--receipts',help='JSON mapping of gate to signed envelope')
    parser.add_argument('--artifacts',required=True,help='local protected proof-artifact directory')
    parser.add_argument('--observe-host',action='store_true',help='read-only probe; cannot close live proof gates')
    args=parser.parse_args(argv)
    try:
        result=evaluate(load_json(args.policy),load_json(args.receipts) if args.receipts else {},Path(args.artifacts))
        if args.observe_host: result['local_observations']=inspect_host()
    except (Rejected,ValueError,OSError) as exc:
        result={'status':'PREFLIGHT_INPUT_REJECTED','reason':str(exc),'execution_authorized':False,'research_executed':False}
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0 if result['status']=='SIGNED_PREFLIGHT_PACKAGE_COMPLETE_PENDING_OWNER_EXECUTION_DECISION' else 2

if __name__=='__main__': raise SystemExit(main())
