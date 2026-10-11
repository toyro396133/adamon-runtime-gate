import copy
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.evidence import LocalEncryptedStore,StorageFailure,canonical,sha
from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader,scope_digest


def chain(tmp_path):
    member=Ed25519PrivateKey.generate();inventory_key=Ed25519PrivateKey.generate()
    scope=scope_digest('a'*64,'attempt1')
    store=LocalEncryptedStore(tmp_path/'encrypted.sqlite',os.urandom(32),member,'member',storage_scope_sha256=scope)
    producer=InventoryProducer(store,required_labels={'sqlite','manifest'},scope_sha256=scope,
        signer=inventory_key,key_id='inventory',member_key=member.public_key(),member_key_id='member')
    def read(inventory,**override):
        args=dict(inventory_sha256=sha(canonical(inventory)),required_labels={'sqlite','manifest'},scope_sha256=scope,
            inventory_key=inventory_key.public_key(),inventory_key_id='inventory',member_key=member.public_key(),member_key_id='member')
        args.update(override)
        return SignedInventoryReader(store,inventory,**args)
    return store,producer,read


def test_actual_encrypted_signed_artifact_roundtrip(tmp_path):
    store,producer,read=chain(tmp_path)
    inventory=producer.seal({'sqlite':b'SQLite synthetic bytes','manifest':b'{"source":"synthetic"}'})
    reader=read(inventory)
    assert reader.read_member('sqlite')==b'SQLite synthetic bytes'
    ref=reader.reference('manifest')
    assert reader.read_version(ref['object_id'],ref['version_id'])==b'{"source":"synthetic"}'
    assert not hasattr(reader,'put')
    with pytest.raises(StorageFailure):reader.read_version(ref['object_id'],'latest')


def test_signature_scope_partial_missing_and_tamper(tmp_path):
    store,producer,read=chain(tmp_path)
    with pytest.raises(StorageFailure):producer.seal({'sqlite':b'x'})
    partial=producer.seal({'sqlite':b'partial'},state='SEALED_PARTIAL')
    with pytest.raises(StorageFailure):read(partial)
    inventory=producer.seal({'sqlite':b'complete','manifest':b'manifest'})
    with pytest.raises(StorageFailure):read(inventory,scope_sha256=scope_digest('a'*64,'attempt2'))
    with pytest.raises(StorageFailure):read(inventory,inventory_sha256='0'*64)
    changed=copy.deepcopy(inventory);changed['members'][0]['evidence']['reference']['version_id']='foreign'
    with pytest.raises(StorageFailure):read(changed)
    with pytest.raises(StorageFailure):read(inventory).read_member('unregistered')
