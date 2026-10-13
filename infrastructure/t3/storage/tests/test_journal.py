"""S3 contract emulator only; no live AWS/preflight acceptance."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import pytest
from infrastructure.t3.storage.tests.test_s3_protected import setup
from infrastructure.t3.storage.journal import JournaledS3Store
from infrastructure.t3.storage.evidence import StorageFailure,canonical,sha
from infrastructure.t3.storage.chain import InventoryProducer
from infrastructure.t3.storage.operations import OperationProducer,OperationSpec


def test_exact_signed_version_reused_and_reread_each_time(tmp_path):
    client,writer,reader=setup();store=JournaledS3Store(writer,reader,ledger=tmp_path/'members.sqlite')
    first=store.put_exact(b'original source');calls=len(client.calls)
    assert store.put_exact(b'original source')==first
    assert any(name=='get' and args['VersionId']==first.reference.version_id for name,args in client.calls[calls:])
    assert len([1 for name,args in client.calls if name=='put'])==1
    client.corrupt=True
    with pytest.raises(StorageFailure,match='readback'):store.put_exact(b'original source')
    client.corrupt=False;assert store.put_exact(b'original source')==first
    with pytest.raises(StorageFailure,match='state/scope'):store.put_exact(b'original source',state='SEALED_PARTIAL')


def test_atomic_concurrent_journal_and_tamper_rejection(tmp_path):
    client,writer,reader=setup();store=JournaledS3Store(writer,reader,ledger=tmp_path/'members.sqlite')
    with ThreadPoolExecutor(max_workers=4) as pool:members=list(pool.map(lambda _:store.put_exact(b'concurrent original'),range(8)))
    assert len({m.reference.version_id for m in members})==1
    assert len([1 for name,args in client.calls if name=='put'])==1
    with sqlite3.connect(store.ledger) as c:
        c.execute('DROP TRIGGER signed_versions_no_update')
        c.execute('UPDATE signed_versions SET envelope=?',(b'{}',))
    with pytest.raises(StorageFailure,match='shape'):store.put_exact(b'concurrent original')


def test_operation_factory_uses_journal_for_actual_protected_s3_adapter(tmp_path):
    client,writer,reader=setup()
    producer=InventoryProducer(writer,required_labels={'before','after','operation_receipt'},scope_sha256=sha(canonical({'bucket':writer.bucket,'prefix':writer.prefix})),signer=writer.signer,key_id=writer.key_id,member_key=writer.signer.public_key(),member_key_id=writer.key_id)
    ops=OperationProducer(inventory_producer=producer,specs={'retry':OperationSpec('a'*64,frozenset({'before','after'}))},producer_identity={'role':'LIFE','case':'synthetic'},signer=writer.signer,ledger=tmp_path/'operations.sqlite')
    inventory=ops.capture('retry','retry',{'before':b'unchanged','after':b'unchanged'})
    assert isinstance(producer.store,JournaledS3Store)
    assert ops.capture('retry','retry',{'before':b'unchanged','after':b'unchanged'})==inventory
    assert len([1 for name,args in client.calls if name=='put'])==2  # one original + receipt
