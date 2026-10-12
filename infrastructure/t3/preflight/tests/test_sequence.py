import copy
import hashlib
import json
from datetime import datetime,timezone
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from infrastructure.t3.preflight.sequence import GATES,canonical,digest,evaluate,validate_policy,Rejected,load_json,main

@pytest.fixture
def fixture(tmp_path):
    keys={role:Ed25519PrivateKey.generate() for role,_,_ in GATES.values()}
    policy={'version':1,'context':{'campaign_id':'NONRESEARCH_CANARY','private_commit':'a'*40,'public_commit':'b'*40,'authority_sha256':'c'*64},'keys':{role:{'role':role,'public_key_hex':key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()} for role,key in keys.items()},'maximum_receipt_age_seconds':3600,'approved_job':{'repository':'toyro396133/adamon-runtime-gate','workflow_ref':'toyro396133/adamon-runtime-gate/.github/workflows/nonresearch.yml@refs/heads/approved-canary','workflow_sha':'b'*40,'run_id':1,'run_attempt':1,'job_id':1}}
    context=validate_policy(policy); (tmp_path/'proof.json').write_bytes(b'{"synthetic_test_only":true}')
    now=datetime(2026,10,12,tzinfo=timezone.utc)
    def sign(payload):
        role=GATES[payload['gate']][0]
        return {'payload':payload,'signature_hex':keys[role].sign(b'ADAMON-PREFLIGHT-V1\n'+canonical(payload)).hex()}
    receipts={}; owner=None
    for gate,(role,kind,requirements) in GATES.items():
        payload={'version':1,'gate':gate,'kind':kind,'signer':role,'issued_at':'2026-10-11T23:59:00Z','expires_at':'2026-10-12T00:59:00Z','context':copy.deepcopy(context),'owner_authorization_sha256':owner,'job':None if gate in ('PF-00','PF-01','PF-09') else {'repository':'toyro396133/adamon-runtime-gate','workflow_ref':'toyro396133/adamon-runtime-gate/.github/workflows/nonresearch.yml@refs/heads/approved-canary','workflow_sha':'b'*40,'run_id':1,'run_attempt':1,'job_id':1},'requirements':dict.fromkeys(requirements,True),'artifacts':[{'name':'proof.json','sha256':hashlib.sha256((tmp_path/'proof.json').read_bytes()).hexdigest(),'size':(tmp_path/'proof.json').stat().st_size,'requirements':list(requirements)}],'status':'PASS'}
        receipts[gate]=sign(payload)
        if gate=='PF-00': owner=digest(receipts[gate])
    return policy,receipts,tmp_path,now,sign

def test_empty_package_all_blocked(fixture):
    p,r,root,now,_=fixture
    result=evaluate(p,{},root,now)
    assert len(result['gates'])==10
    assert {x['state'] for x in result['gates'].values()}=={'BLOCKED'}
    assert not result['execution_authorized']

def test_synthetic_signed_attestations_verify_bytes_but_never_authorize(fixture):
    result=evaluate(*fixture[:3],now=fixture[3])
    assert all(v['state']=='PASS' for v in result['gates'].values())
    assert not result['execution_authorized'] and not result['independent_acceptance_performed']
    assert 'NOT_INDEPENDENT_RUNTIME_OBSERVATION' in result['gates']['PF-04']['verification']

@pytest.mark.parametrize('field,value',[('kind','LOCAL_OS_TESTED'),('version',True),('signer','owner'),('status','VERIFIED'),('expires_at','2020-01-01T00:00:00Z'),('issued_at','2027-01-01T00:00:00Z'),('owner_authorization_sha256','f'*64)])
def test_invalid_signed_claim_fail_closed(fixture,field,value):
    p,r,root,now,sign=fixture
    r['PF-04']['payload'][field]=value;r['PF-04']=sign(r['PF-04']['payload'])
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

def test_modified_payload_bad_signature(fixture):
    p,r,root,now,_=fixture;r['PF-04']['payload']['context']['public_commit']='e'*40
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

@pytest.mark.parametrize('attack',['missing','changed','symlink','wrongsize','traversal','no_coverage','caller_boolean','job_bool','job_repository','unknownfield'])
def test_artifact_and_identity_attacks(fixture,attack):
    p,r,root,now,sign=fixture; payload=r['PF-04']['payload']; item=payload['artifacts'][0]
    if attack=='missing':(root/'proof.json').unlink()
    elif attack=='changed':(root/'proof.json').write_bytes(b'changed')
    elif attack=='symlink':
        (root/'proof.json').rename(root/'actual.json');(root/'proof.json').symlink_to(root/'actual.json')
    elif attack=='wrongsize':item['size']+=1
    elif attack=='traversal':item['name']='../proof.json'
    elif attack=='no_coverage':item['requirements']=item['requirements'][:-1]
    elif attack=='caller_boolean':payload['requirements']['uid_separation']=1
    elif attack=='job_bool':payload['job']['run_attempt']=True
    elif attack=='job_repository':payload['job']['repository']='private/research'
    elif attack=='unknownfield':payload['command']='shell'
    r['PF-04']=sign(payload)
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']!='PASS'

def test_owner_and_reviewer_same_key_rejected(fixture):
    p,*_=fixture;p['keys']['reviewer']['public_key_hex']=p['keys']['owner']['public_key_hex']
    with pytest.raises(Rejected):validate_policy(p)

def test_unknown_gate_rejected(fixture):
    p,r,root,now,_=fixture;r['PF-10']=r['PF-09']
    with pytest.raises(Rejected):evaluate(p,r,root,now)

def test_missing_owner_blocks_other_signatures(fixture):
    p,r,root,now,_=fixture;del r['PF-00']
    assert {v['state'] for v in evaluate(p,r,root,now)['gates'].values()}=={'BLOCKED'}

def test_duplicate_json_key_rejected(tmp_path):
    path=tmp_path/'a';path.write_text('{"a":1,"a":2}')
    with pytest.raises(Rejected):load_json(path)

def test_failed_gate_blocks_independent_final(fixture):
    p,r,root,now,sign=fixture;r['PF-05']['payload']['status']='FAIL';r['PF-05']=sign(r['PF-05']['payload'])
    result=evaluate(p,r,root,now)
    assert result['gates']['PF-05']['state']=='FAIL'
    assert result['gates']['PF-09']['state']=='BLOCKED'

def test_cli_readonly_local_probe_cannot_close_gates(fixture,capsys):
    p,r,root,_,_=fixture;(root/'policy.json').write_text(json.dumps(p))
    assert main(['--policy',str(root/'policy.json'),'--artifacts',str(root),'--observe-host'])==2
    result=json.loads(capsys.readouterr().out)
    assert result['local_observations']['kind']=='NONRESEARCH_READ_ONLY_HOST_PROBE'
    assert {v['state'] for v in result['gates'].values()}=={'BLOCKED'}


def test_replayed_other_job_signed_receipt_rejected(fixture):
    p,r,root,now,sign=fixture
    r['PF-04']['payload']['job']['job_id']=2
    r['PF-04']=sign(r['PF-04']['payload'])
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

def test_attested_false_requirement_cannot_pass(fixture):
    p,r,root,now,sign=fixture
    r['PF-04']['payload']['requirements']['uid_separation']=False
    r['PF-04']=sign(r['PF-04']['payload'])
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

def test_signature_forgery_rejected(fixture):
    p,r,root,now,_=fixture
    r['PF-04']['signature_hex']='00'*64
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

def test_other_source_exact_sha_rejected_even_if_signed(fixture):
    p,r,root,now,sign=fixture
    r['PF-04']['payload']['context']['private_commit']='e'*40
    r['PF-04']=sign(r['PF-04']['payload'])
    assert evaluate(p,r,root,now)['gates']['PF-04']['state']=='FAIL'

def test_verification_keeps_artifacts_exact(fixture):
    p,r,root,now,_=fixture
    before={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir()}
    evaluate(p,r,root,now)
    after={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir()}
    assert after==before

def test_absent_job_authority_rejects_live_receipt(fixture):
    p,r,root,now,sign=fixture
    p['approved_job']=None
    # Re-sign each context as an owner policy change; no fake approved Job.
    context=validate_policy(p);owner=None
    for gate in GATES:
        payload=r[gate]['payload'];payload['context']=context.copy();payload['owner_authorization_sha256']=owner
        r[gate]=sign(payload)
        if gate=='PF-00':owner=digest(r[gate])
    result=evaluate(p,r,root,now)
    assert result['gates']['PF-00']['state']=='PASS'
    assert all(result['gates'][gate]['state']=='FAIL' for gate in list(GATES)[2:9])
    assert result['gates']['PF-09']['state']=='BLOCKED'
