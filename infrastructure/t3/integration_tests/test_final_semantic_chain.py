"""Synthetic transcript -> real encrypted inventory -> real semantic evaluator.

This exercises new closure interfaces, not MICRO execution or a T3 fixture.
Existing assignment/OS canary -> signed Audit/AND remains tested by the joined
nonresearch suite. ELF/namespace privileged execution is separately labelled.
"""
import copy
import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader,scope_digest
from infrastructure.t3.storage.evidence import LocalEncryptedStore,StorageFailure,canonical,sha
from infrastructure.t3.control_semantics import inspect_micro,DIRECT
from infrastructure.t3.micro_evidence import authority_bytes
from infrastructure.t3.tests.test_control_semantics import synthetic
from infrastructure.t3.campaign import report_builder,merge_computed_assertions
from infrastructure.t3.clause_program import evaluate
from infrastructure.t3.authorization import ExecutionBlocked,authorize


def sealed(tmp_path,result,labels=None):
    tmp_path.mkdir(parents=True,exist_ok=True)
    member=Ed25519PrivateKey.generate();signer=Ed25519PrivateKey.generate()
    scope=scope_digest('a'*64,'syntheticFinal')
    store=LocalEncryptedStore(tmp_path/'encrypted.sqlite',os.urandom(32),member,'member',storage_scope_sha256=scope)
    labels={'micro_authority','micro_result'} if labels is None else labels
    producer=InventoryProducer(store,required_labels=labels,scope_sha256=scope,signer=signer,key_id='inventory',member_key=member.public_key(),member_key_id='member')
    from infrastructure.t3.capture_encoding import encode
    data={'micro_authority':authority_bytes(DIRECT),'micro_result':encode(result)}
    inventory=producer.seal({key:data[key] for key in labels})
    def reader(inv=inventory):
        return SignedInventoryReader(store,inv,inventory_sha256=sha(canonical(inv)),required_labels=labels,scope_sha256=scope,inventory_key=signer.public_key(),inventory_key_id='inventory',member_key=member.public_key(),member_key_id='member')
    return reader,inventory


def test_signed_original_semantics_reach_exact_clause_router_no_research_pass(tmp_path):
    read,_=sealed(tmp_path,synthetic());result=inspect_micro(DIRECT,read())
    assert all(result['assertions'].values())
    report=report_builder({})
    merge_computed_assertions(report['gates']['R2-LL2-A']['partial_assertions'],result['assertions'])
    clauses=evaluate(report)['R2-LL2-A']
    assert clauses['clauses'][0]['state']=='SUPPORTED_BY_COMPUTED_ASSERTIONS'
    assert clauses['clauses'][1]['state']=='MISSING_COMPUTATION'
    assert not clauses['can_close_gate'] and not clauses['scientific_acceptance']
    with pytest.raises(ExecutionBlocked,match='NOT FROZEN'):authorize(None,'MICRO',DIRECT)


@pytest.mark.parametrize('mutation',('wrong_source','forged_trace','duplicate_capture'))
def test_semantic_mutation_rejected_even_with_valid_encryption_and_signatures(tmp_path,mutation):
    baseline=synthetic();read,_=sealed(tmp_path/'baseline',baseline)
    inspect_micro(DIRECT,read())
    bad=copy.deepcopy(baseline)
    if mutation=='wrong_source':bad['authority_metadata']['source_sha256']={'injected':'0'*64}
    elif mutation=='forged_trace':bad['transcripts']['ten_successes'][4]['events'][next(iter(bad['transcripts']['ten_successes'][4]['events']))]['realization_delta']=.9
    else:bad['transcripts']['ten_successes'].append(copy.deepcopy(bad['transcripts']['ten_successes'][-1]))
    read_bad,_=sealed(tmp_path/'mutated',bad)
    with pytest.raises(ExecutionBlocked):inspect_micro(DIRECT,read_bad())
    inspect_micro(DIRECT,read())


def test_signed_inventory_version_substitution_is_not_semantic_input(tmp_path):
    read,inventory=sealed(tmp_path,synthetic());inspect_micro(DIRECT,read())
    modified=copy.deepcopy(inventory);modified['members'][0]['evidence']['reference']['version_id']='latest'
    with pytest.raises(StorageFailure):read(modified)


def test_missing_original_member_cannot_be_replaced_by_claimed_success(tmp_path):
    read,_=sealed(tmp_path,synthetic(),labels={'micro_authority'})
    with pytest.raises(StorageFailure):inspect_micro(DIRECT,read())
