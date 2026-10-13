"""Real local crypto/I/O integration, synthetic artifacts, no research execution."""
import hashlib
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.roles.receipts import ReceiptError,seal,canonical
from infrastructure.t3.roles.artifacts import EvidenceAudit
from infrastructure.t3.roles.aggregation import Aggregator,CampaignRegistry
from infrastructure.t3.storage.inventory import create_inventory
from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader,scope_digest
from infrastructure.t3.storage.evidence import LocalEncryptedStore,canonical as storage_canonical,sha
from infrastructure.t3.roles.tests import test_receipts as receipt_fixtures


def test_signed_producer_actual_artifact_audit_manifest(tmp_path):
    fixture=receipt_fixtures.Receipts();fixture.setUp()
    fixture.p['role']='LIFE';fixture.p['state']='SEALED_COMPLETE'
    from dataclasses import replace
    from infrastructure.t3.roles.receipts import ReceiptVerifier
    authority=fixture.v.authority
    keys=dict(authority.keys);keys[('LIFE','k')]=keys[('AUDIT','k')]
    domains=dict(authority.domains);domains['LIFE']='SYNTHETIC'
    bindings={key:dict(value) for key,value in authority.permit_bindings.items()};bindings['p']['role']='LIFE'
    fixture.v=ReceiptVerifier(replace(authority,keys=keys,domains=domains,permit_bindings=bindings))
    receipt=seal(fixture.p,'LIFE','SYNTHETIC',fixture.key)
    storage_key=Ed25519PrivateKey.generate();inv_key=Ed25519PrivateKey.generate()
    scope=scope_digest('a'*64,'attempt1')
    store=LocalEncryptedStore(tmp_path/'actual-encrypted.sqlite',os.urandom(32),storage_key,'storage',storage_scope_sha256=scope)
    producer=InventoryProducer(store,required_labels={'artifact'},scope_sha256=scope,signer=inv_key,key_id='inventory',member_key=storage_key.public_key(),member_key_id='storage')
    inventory=producer.seal({'artifact':b'actual signed encrypted local test artifact'})
    pinned_inventory_digest=sha(storage_canonical(inventory))
    def factory(payload,inv):
        assert payload['case']=='dummy'
        return SignedInventoryReader(store,inv,inventory_sha256=pinned_inventory_digest,required_labels={'artifact'},scope_sha256=scope,
            inventory_key=inv_key.public_key(),inventory_key_id='inventory',member_key=storage_key.public_key(),member_key_id='storage')
    def evaluator(subject,reader):
        assert reader.read_member('artifact')==b'actual signed encrypted local test artifact'
        return {'gates':{},'controls':{},'failures':0,'errors':0,'skips':0}
    audit=EvidenceAudit(fixture.v,reader_factory=factory,evaluator=evaluator,registered_subjects={'dummy':'LIFE'})
    manifest=audit.inspect(receipt,inventory)
    assert manifest['producer_receipt_sha256']==hashlib.sha256(canonical(fixture.p)).hexdigest()
    sealed=audit.seal_manifest(manifest,store=store)
    assert store.read(sealed)==storage_canonical(manifest)
    # Actual aggregation reads the sealed audit manifest through the same
    # signed immutable reader, not an in-memory truth/result substitute.
    audit_inventory=create_inventory({'audit_manifest':sealed},state='SEALED_COMPLETE',signer=inv_key,key_id='inventory',
        trusted_member_key=storage_key.public_key(),trusted_member_key_id='storage')
    aggregation_reader=SignedInventoryReader(store,audit_inventory,inventory_sha256=sha(storage_canonical(audit_inventory)),
        required_labels={'audit_manifest'},scope_sha256=scope,inventory_key=inv_key.public_key(),inventory_key_id='inventory',
        member_key=storage_key.public_key(),member_key_id='storage')
    life=tuple('case'+str(i) for i in range(27));gates=tuple('gate'+str(i) for i in range(23));micro=('micro0','micro1')
    registry=CampaignRegistry(life,micro,gates,('control0',),{case:10 for case in life},gates[0],
        {m:{'life_cycles':1,'structural_direct_processings':0,'direct_batch_calls':0,'fixture_sha256':'a'*64,'schedule_sha256':'b'*64,'registry_sha256':'c'*64} for m in micro},
        {g:{'verified':True} for g in gates},{'control0':{'performed':True}})
    aggregator=Aggregator(registry,fixture.v,aggregation_reader)
    assert aggregator._manifest(aggregation_reader.reference('audit_manifest'))==manifest
    with pytest.raises(ReceiptError):aggregator.evaluate([])
    with pytest.raises(ReceiptError):aggregator.finalize([],{},storage_key,None)
    # A swapped receipt or role cannot unlock evidence evaluation.
    forged=dict(fixture.p,case='unregistered')
    with pytest.raises(ReceiptError):audit.inspect(seal(forged,'LIFE','SYNTHETIC',fixture.key),inventory)
    with pytest.raises(ReceiptError):EvidenceAudit(fixture.v,reader_factory=factory,evaluator=evaluator,registered_subjects={'dummy':'AUDIT'}).inspect(receipt,inventory)
