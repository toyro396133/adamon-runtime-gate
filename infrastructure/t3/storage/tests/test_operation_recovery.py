"""Exact original reuse/recovery; local cryptographic store, not live AWS."""
import concurrent.futures
import sqlite3
import pytest
from infrastructure.t3.storage.tests.test_operations import Campaign
from infrastructure.t3.storage.evidence import StorageFailure


def test_identical_original_across_distinct_operations_has_same_exact_version(tmp_path):
    c=Campaign(tmp_path)
    original=c.inspect_operation()
    inv=c.ops.capture('second','capture',dict(original.members))
    ref=next(m['evidence']['reference'] for m in inv['members'] if m['label']=='artifact')
    assert ref==original.references['artifact']
    assert c.store.read(c.producer.store.put_exact(original.members['artifact']))==original.members['artifact']


def test_interrupted_seal_recovers_original_versions_without_mutation(tmp_path):
    c=Campaign(tmp_path);baseline=c.aggregator().evaluate(c.receipts)
    seal=c.producer.seal
    captured=[]
    def interrupted(*args,**kwargs):
        captured.append(seal(*args,**kwargs))
        raise StorageFailure('injected crash after immutable seal')
    c.producer.seal=interrupted
    with pytest.raises(StorageFailure,match='injected crash'):
        c.ops.capture('crash','capture',{'artifact':b'new original crash bytes'})
    c.producer.seal=seal
    restored=c.ops.capture('crash','capture',{'artifact':b'new original crash bytes'})
    assert restored==captured[0]
    assert c.ops.capture('crash','capture',{'artifact':b'new original crash bytes'})==restored
    assert c.aggregator().evaluate(c.receipts)==baseline


def test_concurrent_exact_reuse_is_atomic_and_state_cannot_upgrade(tmp_path):
    c=Campaign(tmp_path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        members=list(pool.map(lambda _:c.store.put_exact(b'concurrent original'),range(12)))
    assert len({m.reference.version_id for m in members})==1
    partial=c.store.put_exact(b'partial only',state='SEALED_PARTIAL')
    with pytest.raises(StorageFailure,match='state/scope'):
        c.store.put_exact(b'partial only')
    assert c.store.read(partial)==b'partial only'
    with pytest.raises(StorageFailure,match='create-only'):
        c.store.put(b'concurrent original')


def test_existing_ciphertext_tamper_cannot_be_reused(tmp_path):
    c=Campaign(tmp_path);member=c.store.put_exact(b'tamper target')
    with sqlite3.connect(c.store.database) as con:
        con.execute('DROP TRIGGER no_update')
        con.execute('UPDATE versions SET ciphertext=? WHERE object_id=?',(b'bad',member.reference.object_id))
    with pytest.raises(StorageFailure,match='encryption integrity'):
        c.store.put_exact(b'tamper target')


def test_identical_registered_members_reuse_only_exact_signed_envelope(tmp_path):
    from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader
    from infrastructure.t3.storage.inventory import create_inventory
    from infrastructure.t3.storage.evidence import canonical,sha,signed
    c=Campaign(tmp_path);labels={'before','after'}
    producer=InventoryProducer(c.store,required_labels=labels,scope_sha256=c.scope,signer=c.inventory_key,key_id='inventory',member_key=c.storage_key.public_key(),member_key_id='storage')
    inv=producer.seal({'before':b'idempotent original','after':b'idempotent original'})
    def reader(inv):return SignedInventoryReader(c.store,inv,inventory_sha256=sha(canonical(inv)),required_labels=labels,scope_sha256=c.scope,inventory_key=c.inventory_key.public_key(),inventory_key_id='inventory',member_key=c.storage_key.public_key(),member_key_id='storage')
    actual=reader(inv)
    assert actual.reference('before')==actual.reference('after')
    assert actual.read_member('before')==actual.read_member('after')==b'idempotent original'
    original=c.store.put_exact(b'idempotent original')
    forged=signed(original.reference,original.state,'2100-01-01T00:00:00+00:00','storage',c.storage_key,c.scope)
    contradictory=create_inventory({'before':original,'after':forged},state='SEALED_COMPLETE',signer=c.inventory_key,key_id='inventory',trusted_member_key=c.storage_key.public_key(),trusted_member_key_id='storage')
    with pytest.raises(StorageFailure,match='contradictory artifact'):
        reader(contradictory)
    assert reader(inv).read_member('before')==b'idempotent original'
