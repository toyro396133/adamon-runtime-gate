"""Wire-shape and negative contracts, not a live GitHub assignment proof."""
import copy
import hashlib
import json
import pytest
from infrastructure.t3.runner.assignment import decode_assignment, MARKER

def dictionary(value):
    return {'t':2,'d':[{'k':k,'v':v} for k,v in value.items()]}

def packet():
    return {'jobId':'11111111-1111-1111-1111-111111111111','plan':{'planId':'22222222-2222-2222-2222-222222222222'},'requestId':1,
    'contextData':{'github':dictionary({'repository_id':'567','run_id':'123','run_attempt':'2','repository':'owner/repo','ref':'refs/heads/approved','sha':'a'*40}),
    'job':dictionary({'check_run_id':345.0,'workflow_ref':'owner/repo/.github/workflows/pinned.yml@refs/heads/approved','workflow_sha':'a'*40})},
    'steps':[{'id':'33333333-3333-3333-3333-333333333333','type':4,'reference':{'type':3},'condition':'success()',
    'inputs':{'type':2,'map':[{'key':'script','value':MARKER}]}}]}

def decode(value):
    raw=json.dumps(value);return decode_assignment(raw,hashlib.sha256(raw.encode()).hexdigest())

def test_numeric_domains_stay_distinct():
    result=decode(packet());assert result['check_run_id']==345;assert 'job_id' not in result;assert 'runner_id' not in result;assert result['repository_id']==567;assert len(result['step_sha256'])==64

def test_hash_binding():
    with pytest.raises(ValueError,match='DIGEST'):decode_assignment(json.dumps(packet()),'0'*64)

@pytest.mark.parametrize('change',[
 lambda p:p['steps'][0]['inputs']['map'][0].update(value='echo evil'),
 lambda p:p['steps'][0].update(reference={'type':1}),
 lambda p:p.update(enableDebugger=True),
 lambda p:p['contextData']['job']['d'][0].update(v=True),
 lambda p:p['contextData']['job']['d'][0].update(v=2**54),
 lambda p:p['contextData']['job']['d'].append({'k':'CHECK_RUN_ID','v':999}),
 lambda p:p['steps'].append(copy.deepcopy(p['steps'][0])),
 lambda p:p['contextData']['github']['d'].append({'k':'workflow_sha','v':'b'*40}),
])
def test_closed_negative_shapes(change):
    value=packet();change(value)
    with pytest.raises(ValueError):decode(value)

def test_duplicate_json_case_denied():
    raw='{"JobId":"a","jobid":"b"}'
    with pytest.raises(ValueError,match='DUPLICATE'):decode_assignment(raw,hashlib.sha256(raw.encode()).hexdigest())

def test_repository_identity_required():
    value=packet();value['contextData']['github']['d']=[p for p in value['contextData']['github']['d'] if p['k']!='repository_id']
    with pytest.raises(ValueError,match='SAFE_INTEGER'):decode(value)

def test_step_digest_binds_entire_step():
    first=packet();second=copy.deepcopy(first);second['steps'][0]['displayName']='other approved-display'
    assert decode(first)['step_sha256'] != decode(second)['step_sha256']
