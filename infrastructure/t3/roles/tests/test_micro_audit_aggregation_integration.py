"""IMP001-R02: actual crypto/storage/Audit/Aggregator, synthetic contracts only.

No private fixture contents, accepted research IDs, MICRO/Life calls or research
permit. The 27/2/23/12 cardinalities exercise the unchanged production registry.
All audit assertions below refer to fixed synthetic bytes, never scientific PASS.
"""
import copy
import hashlib
import os
import json
from dataclasses import asdict
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.roles.receipts import ReceiptAuthority, ReceiptVerifier, ReceiptError, canonical, seal
from infrastructure.t3.roles.micro_authority import MicroAuthorityPins
from infrastructure.t3.roles.artifacts import EvidenceAudit
from infrastructure.t3.roles.aggregation import CampaignRegistry, Aggregator
from infrastructure.t3.storage.chain import SignedInventoryReader, scope_digest
from infrastructure.t3.storage.inventory import create_inventory, verify_inventory
from infrastructure.t3.storage.evidence import LocalEncryptedStore, StorageFailure


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


class SyntheticCampaign:
    """Test-owned keys/schema/permit bindings; no research authorization authority."""
    def __init__(self, directory):
        self.directory=directory;self.witnesses=[]
        self.life=tuple(f'synthetic_life_{i}' for i in range(27))
        self.micro=tuple(f'synthetic_micro_{i}' for i in range(2))
        self.gates=tuple(f'synthetic_gate_{i}' for i in range(23))
        self.controls=tuple(f'synthetic_control_{i}' for i in range(12))
        self.keys={role:Ed25519PrivateKey.generate() for role in ('LIFE','MICRO','AUDIT')}
        self.domains={role:'NONRESEARCH_SYNTHETIC_R02_'+role for role in self.keys}
        self.storage_key=Ed25519PrivateKey.generate();self.inventory_key=Ed25519PrivateKey.generate()
        self.scope=scope_digest('a'*64,'syntheticattempt')
        self.store=LocalEncryptedStore(directory/'synthetic-encrypted.sqlite',os.urandom(32),
            self.storage_key,'storage',storage_scope_sha256=self.scope)
        self.metadata={subject:dict(authority_version='MICRO_V4_1',control_id=subject,
            jobs_sha256='b'*64,registry_sha256='c'*64,fixture_sha256='d'*64,
            schedule_sha256='e'*64,life_cycles=1,structural_direct_processings=0,direct_batch_calls=0)
            for subject in self.micro}
        self.pins={subject:MicroAuthorityPins(value) for subject,value in self.metadata.items()}
        fields=('registry_sha256','fixture_sha256','schedule_sha256','life_cycles',
                'structural_direct_processings','direct_batch_calls')
        self.registry=CampaignRegistry(self.life,self.micro,self.gates,self.controls,
            {s:1 for s in self.life},self.gates[0],
            {s:{k:self.metadata[s][k] for k in fields} for s in self.micro},
            {s:{'synthetic_bytes_checked':True} for s in self.gates},
            {s:{'synthetic_bytes_checked':True} for s in self.controls},self.pins)
        self.subjects={**{s:'LIFE' for s in self.life},**{s:'MICRO' for s in self.micro}}
        self.payloads={};self.members={};self.inventories={};self.sealed_manifests={}
        self.manifests={};self.receipts=[];self.evaluator_calls=[];bindings={}
        common=dict(authority_sha256='a'*64,source_sha256='f'*64,environment_sha256='1'*64,
            run_id='synthetic-run',job_id='synthetic-job',run_attempt='synthetic-attempt',
            host_id='synthetic-host',session_id='synthetic-session',boot_id='synthetic-boot',
            dispatch_id='synthetic-dispatch',worker_instance_id='synthetic-worker',
            worker_job_guid='synthetic-guid',worker_request_id='synthetic-request',plan_guid='synthetic-plan',
            listener_binary_sha256='2'*64,worker_binary_sha256='3'*64,launcher_binary_sha256='4'*64,
            assignment_sha256='5'*64,worker_uid='synthetic-worker-uid',launcher_uid='synthetic-launcher-uid',
            worker_start_monotonic_ns='synthetic-worker-start',launcher_start_monotonic_ns='synthetic-launcher-start',
            worker_pidfd_registry_id='synthetic-worker-pidfd',launcher_pidfd_registry_id='synthetic-launcher-pidfd',
            cgroup_identity='synthetic-cgroup')
        for subject,producer_role in self.subjects.items():
            members={'artifact':self.store.put(('NONRESEARCH:'+subject).encode())}
            if subject in self.micro:members['micro_authority']=self.store.put(canonical(self.metadata[subject]))
            self.members[subject]=members;self.inventories[subject]=self.inventory(members)
            for role in (producer_role,'AUDIT'):
                selector={'case':subject} if subject in self.life else {'control_id':subject}
                payload=dict(common,**selector,role=role,permit_id=role+'_'+subject,
                    signer_key_id=role,state='AUDIT_PASS' if role=='AUDIT' else 'SEALED_COMPLETE')
                if subject in self.micro:payload.update({k:self.metadata[subject][k] for k in fields})
                if role=='LIFE':payload['completed_cycles']=1
                if role!='AUDIT':payload['inventory_sha256']=digest(self.inventories[subject])
                self.payloads[(role,subject)]=payload
                bindings[payload['permit_id']]=dict(common,**selector,role=role)
        # Closed synthetic schema, explicitly NOT the private research schema.
        variants=[]
        for role,subject in self.payloads:
            payload=self.payloads[(role,subject)]
            props={k:{'type':'integer' if type(v) is int else 'string'} for k,v in payload.items()}
            props['role']={'const':role}
            if role=='AUDIT':props['audit_manifest']={'type':'object','required':['object_id','version_id','sha256','size_bytes'],
                'additionalProperties':False,'properties':{**{k:{'type':'string'} for k in ('object_id','version_id','sha256')},'size_bytes':{'type':'integer','minimum':1}}}
            variant={'type':'object','required':list(props),'additionalProperties':False,'properties':props}
            if variant not in variants:variants.append(variant)
        schema=canonical({'$defs':{'signed_private_receipt':{'type':'object','required':['payload','signature'],
            'additionalProperties':False,'properties':{'payload':{'oneOf':variants},'signature':{'type':'string','pattern':'^[0-9a-f]{128}$'}}}}})
        authority=ReceiptAuthority('a'*64,'f'*64,'1'*64,
            {(role,role):key.public_key().public_bytes_raw() for role,key in self.keys.items()},
            self.domains,schema,hashlib.sha256(schema).hexdigest(),bindings)
        self.verifier=ReceiptVerifier(authority)
        self.audit=EvidenceAudit(self.verifier,reader_factory=self.reader_factory,evaluator=self.evaluator,
            registered_subjects=self.subjects,micro_authorities=self.pins)
        for subject,role in self.subjects.items():
            producer=self.sign(self.payloads[(role,subject)])
            manifest=self.audit.inspect(producer,self.inventories[subject])
            self.manifests[subject]=manifest
            sealed=self.audit.seal_manifest(manifest,store=self.store)
            self.sealed_manifests[subject]=sealed
            audit_payload=dict(self.payloads[('AUDIT',subject)],audit_manifest=asdict(sealed.reference))
            self.receipts.extend((producer,self.sign(audit_payload)))
        assert len(self.evaluator_calls)==29

    def witness(self,label,stage,error):
        self.witnesses.append(dict(mutation=label,stage=stage,error=str(error),baseline_positive=True))

    def sign(self,payload):
        role=payload['role'];return seal(payload,role,self.domains[role],self.keys[role])

    def inventory(self,members):
        return create_inventory(members,state='SEALED_COMPLETE',signer=self.inventory_key,key_id='inventory',
            trusted_member_key=self.storage_key.public_key(),trusted_member_key_id='storage')

    def reader(self,inventory,labels,pinned_digest):
        return SignedInventoryReader(self.store,inventory,inventory_sha256=pinned_digest,
            required_labels=labels,scope_sha256=self.scope,inventory_key=self.inventory_key.public_key(),
            inventory_key_id='inventory',member_key=self.storage_key.public_key(),member_key_id='storage')

    def reader_factory(self,payload,inventory):
        subject=payload.get('case',payload.get('control_id'))
        labels={'artifact','micro_authority'} if subject in self.micro else {'artifact'}
        return self.reader(inventory,labels,payload['inventory_sha256'])

    def evaluator(self,subject,reader):
        assert reader.read_member('artifact')==('NONRESEARCH:'+subject).encode()
        self.evaluator_calls.append(subject)
        gates={g:dict(self.registry.gate_assertions[g]) for g in self.gates} if subject==self.life[0] else {}
        controls={}
        if subject in self.micro:
            index=self.micro.index(subject)
            controls={g:dict(self.registry.control_assertions[g]) for g in self.controls[index*6:(index+1)*6]}
        return dict(gates=gates,controls=controls,failures=0,errors=0,skips=0)

    def aggregator(self):
        members={'audit_'+str(i):self.sealed_manifests[s] for i,s in enumerate(self.subjects)}
        inventory=self.inventory(members)
        return Aggregator(self.registry,self.verifier,self.reader(inventory,members,digest(inventory)))

    def valid(self):
        for envelope in self.receipts:
            p=envelope['payload'];self.verifier.verify(envelope,p['role'],p.get('case',p.get('control_id')))
        assert self.aggregator().evaluate(self.receipts)=={'overall_pass':True}
        return True

    def replace_manifest(self,subject,raw):
        sealed=self.store.put(raw);self.sealed_manifests[subject]=sealed
        receipts=copy.deepcopy(self.receipts)
        for index,envelope in enumerate(receipts):
            p=envelope['payload']
            if p['role']=='AUDIT' and p.get('control_id')==subject:
                receipts[index]=self.sign(dict(p,audit_manifest=asdict(sealed.reference)))
        return receipts


@pytest.fixture
def campaign(tmp_path):
    result=SyntheticCampaign(tmp_path)
    assert result.valid()  # Every negative starts with a complete positive flow.
    yield result
    (tmp_path/'mutation_witness.json').write_text(json.dumps(dict(
        scope='NONRESEARCH_SYNTHETIC_R02',baseline_receipts=58,
        baseline_roles=['LIFE','MICRO','AUDIT'],registry_cardinality=[27,2,23,12],
        baseline_receipts_sha256=digest(result.receipts),positive_baseline_evaluated=True,
        witnesses=result.witnesses),indent=2)+'\n')


def test_complete_micro_signed_inventory_audit_receipts_aggregation(campaign):
    assert len(campaign.receipts)==58
    assert isinstance(campaign.store,LocalEncryptedStore)
    assert isinstance(campaign.aggregator().reader,SignedInventoryReader)
    assert campaign.valid()
    with campaign.store._connect() as connection:
        assert all(b'NONRESEARCH:' not in row[0] for row in connection.execute('SELECT ciphertext FROM versions'))


@pytest.mark.parametrize('field,value',[
    ('schedule_sha256','0'*64),('jobs_sha256',None),('jobs_sha256','0'*64),
    ('jobs_sha256',True),('life_cycles',2)],
    ids=['retired_schedule','missing_jobs','incorrect_jobs','wrong_type_jobs','signed_metadata_mismatch'])
def test_isolated_signed_micro_metadata_rejected_by_audit_and_aggregation(campaign,field,value):
    subject=campaign.micro[0];baseline=campaign.metadata[subject];changed=dict(baseline)
    if value is None:changed.pop(field)
    else:changed[field]=value
    assert {k for k in baseline.keys()|changed.keys() if k not in changed or type(changed[k]) is not type(baseline[k]) or changed[k]!=baseline[k]}=={field}
    assert campaign.pins[subject].verify_metadata(baseline)==baseline
    members=dict(campaign.members[subject]);members['micro_authority']=campaign.store.put(canonical(changed))
    inventory=campaign.inventory(members)
    # Prove valid signatures, storage versions, receipt/job binding and labels;
    # the only altered authority content is the one declared metadata field.
    verify_inventory(inventory,public_key=campaign.inventory_key.public_key(),key_id='inventory',
        required_labels=members,trusted_member_key=campaign.storage_key.public_key(),trusted_member_key_id='storage')
    payload=dict(campaign.payloads[('MICRO',subject)],inventory_sha256=digest(inventory))
    producer=campaign.sign(payload)
    campaign.verifier.verify(producer,'MICRO',subject)
    campaign.pins[subject].verify_receipt(payload)
    assert campaign.reader_factory(payload,inventory).read_member('micro_authority')==canonical(changed)
    calls=len(campaign.evaluator_calls)
    with pytest.raises(ReceiptError,match='^MICRO authority/jobs/fixture/schedule mismatch$') as failure:
        campaign.audit.inspect(producer,inventory)
    campaign.witness(field+':'+str(value),'EvidenceAudit.inspect',failure.value)
    assert len(campaign.evaluator_calls)==calls
    manifest=copy.deepcopy(campaign.manifests[subject]);manifest['micro_authority']=changed
    receipts=campaign.replace_manifest(subject,canonical(manifest))
    with pytest.raises(ReceiptError,match='^MICRO authority/jobs/fixture/schedule mismatch$') as failure:
        campaign.aggregator().evaluate(receipts)
    campaign.witness(field+':'+str(value),'Aggregator.evaluate',failure.value)


def test_missing_micro_authority_member_rejected_at_real_inventory_reader(campaign):
    subject=campaign.micro[0];members=dict(campaign.members[subject]);members.pop('micro_authority')
    inventory=campaign.inventory(members)
    verify_inventory(inventory,public_key=campaign.inventory_key.public_key(),key_id='inventory',
        required_labels=members,trusted_member_key=campaign.storage_key.public_key(),trusted_member_key_id='storage')
    producer=campaign.sign(dict(campaign.payloads[('MICRO',subject)],inventory_sha256=digest(inventory)))
    campaign.verifier.verify(producer,'MICRO',subject)
    calls=len(campaign.evaluator_calls)
    with pytest.raises(StorageFailure,match='^exact approved artifact inventory mismatch$') as failure:
        campaign.audit.inspect(producer,inventory)
    campaign.witness('missing_micro_authority_member','EvidenceAudit.inspect',failure.value)
    assert len(campaign.evaluator_calls)==calls
    assert campaign.valid()


@pytest.mark.parametrize('mutation,reason',[
    ('invalid_json','invalid manifest JSON'),
    ('wrong_authority','MICRO authority/jobs/fixture/schedule mismatch'),
    ('wrong_producer','audit producer mismatch')])
def test_isolated_audit_manifest_mutations_reach_actual_aggregator(campaign,mutation,reason):
    subject=campaign.micro[0];original=campaign.manifests[subject];changed=copy.deepcopy(original)
    if mutation=='invalid_json':raw=b'NOT_JSON_NONRESEARCH'
    elif mutation=='wrong_authority':
        changed['micro_authority']['fixture_sha256']='0'*64
        assert {k for k in original if original[k]!=changed[k]}=={'micro_authority'}
        raw=canonical(changed)
    else:
        changed['producer_receipt_sha256']='0'*64
        assert {k for k in original if original[k]!=changed[k]}=={'producer_receipt_sha256'}
        raw=canonical(changed)
    receipts=campaign.replace_manifest(subject,raw)
    for envelope in receipts:
        p=envelope['payload'];campaign.verifier.verify(envelope,p['role'],p.get('case',p.get('control_id')))
    with pytest.raises(ReceiptError,match='^'+reason+'$') as failure:campaign.aggregator().evaluate(receipts)
    campaign.witness(mutation,'Aggregator.evaluate',failure.value)


@pytest.mark.parametrize('role,operation,reason',[
    ('MICRO','missing','missing life/micro/audit'),('MICRO','duplicate','unexpected/duplicate receipt'),
    ('AUDIT','missing','missing life/micro/audit'),('AUDIT','duplicate','unexpected/duplicate receipt')])
def test_isolated_producer_or_audit_receipt_set_mutation(campaign,role,operation,reason):
    subject=campaign.micro[0];receipts=copy.deepcopy(campaign.receipts)
    index=next(i for i,e in enumerate(receipts) if e['payload']['role']==role and e['payload'].get('control_id')==subject)
    original=receipts[index]
    if operation=='missing':receipts.pop(index)
    else:receipts.append(copy.deepcopy(original))
    assert len(receipts)==58+(-1 if operation=='missing' else 1)
    for envelope in receipts:
        p=envelope['payload'];campaign.verifier.verify(envelope,p['role'],p.get('case',p.get('control_id')))
    with pytest.raises(ReceiptError,match='^'+reason+'$') as failure:campaign.aggregator().evaluate(receipts)
    campaign.witness(role+':'+operation,'Aggregator.evaluate',failure.value)
    assert campaign.valid()


def test_finalize_stays_disabled_after_complete_positive_evaluation(campaign):
    aggregator=campaign.aggregator()
    assert aggregator.evaluate(campaign.receipts)=={'overall_pass':True}
    with pytest.raises(ReceiptError,match='^terminal execution authority not frozen; PASS_TOTAL signing disabled$') as failure:
        aggregator.finalize(campaign.receipts,{},Ed25519PrivateKey.generate(),None)
    campaign.witness('finalize','Aggregator.finalize',failure.value)


def test_stale_producer_schedule_rejected_after_valid_receipt_verification(campaign):
    subject=campaign.micro[0];payload=dict(campaign.payloads[('MICRO',subject)])
    payload['schedule_sha256']='0'*64
    producer=campaign.sign(payload)
    assert campaign.verifier.verify(producer,'MICRO',subject)==payload
    calls=len(campaign.evaluator_calls)
    with pytest.raises(ReceiptError,match='^MICRO receipt not bound to active authority$') as failure:
        campaign.audit.inspect(producer,campaign.inventories[subject])
    campaign.witness('retired_producer_schedule','EvidenceAudit.inspect',failure.value)
    assert len(campaign.evaluator_calls)==calls
    # Keep the dependent producer digest valid: this negative cannot succeed
    # accidentally because of a second audit-producer mismatch.
    manifest=copy.deepcopy(campaign.manifests[subject])
    manifest['producer_receipt_sha256']=digest(payload)
    receipts=campaign.replace_manifest(subject,canonical(manifest))
    index=next(i for i,e in enumerate(receipts) if e['payload']['role']=='MICRO' and e['payload'].get('control_id')==subject)
    receipts[index]=producer
    assert manifest['producer_receipt_sha256']==digest(receipts[index]['payload'])
    for envelope in receipts:
        p=envelope['payload'];campaign.verifier.verify(envelope,p['role'],p.get('case',p.get('control_id')))
    with pytest.raises(ReceiptError,match='^micro fixture/count mismatch$') as failure:
        campaign.aggregator().evaluate(receipts)
    campaign.witness('retired_producer_schedule','Aggregator.evaluate',failure.value)
