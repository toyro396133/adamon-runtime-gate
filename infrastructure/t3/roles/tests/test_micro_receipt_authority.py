"""Generic byte and crypto binding, no private scientific fixture contents."""
import hashlib
import json
import pytest
from infrastructure.t3.roles.micro_authority import MicroAuthorityPins
from infrastructure.t3.roles.receipts import ReceiptError


def metadata():
    return dict(authority_version='MICRO_V4_1',control_id='synthetic-control',
                jobs_sha256='1'*64,registry_sha256='2'*64,fixture_sha256='3'*64,
                schedule_sha256='4'*64,life_cycles=0,structural_direct_processings=12,direct_batch_calls=36)

class Reader:
    def __init__(self,data):self.raw=json.dumps(data).encode()
    def reference(self,label):
        assert label=='micro_authority'
        return dict(object_id=hashlib.sha256(self.raw).hexdigest(),version_id='v1',sha256=hashlib.sha256(self.raw).hexdigest(),size_bytes=len(self.raw))
    def read_version(self,object_id,version_id):return self.raw

def test_audit_reads_actual_version_bytes():
    expected=metadata();pins=MicroAuthorityPins(expected)
    assert pins.inspect_reader(Reader(expected))==expected

@pytest.mark.parametrize('field',list(metadata()))
def test_changed_every_metadata_field_fails(field):
    expected=metadata();pins=MicroAuthorityPins(expected);actual=dict(expected)
    actual[field]=True if type(actual[field]) is int else 'forged'
    with pytest.raises(ReceiptError):pins.inspect_reader(Reader(actual))

def test_receipt_counts_are_type_sensitive():
    expected=metadata();pins=MicroAuthorityPins(expected)
    pins.verify_receipt(expected)
    expected['life_cycles']=False
    with pytest.raises(ReceiptError):pins.verify_receipt(expected)

def test_required_active_version_and_complete_closed_fields():
    for changed in ({**metadata(),'authority_version':'MICRO_V4'}, {k:v for k,v in metadata().items() if k!='jobs_sha256'}, {**metadata(),'path':'/tmp/alternative'}):
        with pytest.raises(ReceiptError):MicroAuthorityPins(changed)


def test_metadata_uses_real_signed_encrypted_immutable_inventory(tmp_path):
    """Actual Ed25519/AES-GCM/SQLite I/O, synthetic metadata, no research run."""
    import os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader,scope_digest
    from infrastructure.t3.storage.evidence import LocalEncryptedStore,canonical,sha
    member_key=Ed25519PrivateKey.generate();inventory_key=Ed25519PrivateKey.generate()
    scope=scope_digest('a'*64,'syntheticattempt')
    store=LocalEncryptedStore(tmp_path/'encrypted.sqlite',os.urandom(32),member_key,'member',storage_scope_sha256=scope)
    producer=InventoryProducer(store,required_labels={'micro_authority'},scope_sha256=scope,
        signer=inventory_key,key_id='inventory',member_key=member_key.public_key(),member_key_id='member')
    expected=metadata();pins=MicroAuthorityPins(expected)
    def reader_for(actual):
        inventory=producer.seal({'micro_authority':canonical(actual)})
        return SignedInventoryReader(store,inventory,inventory_sha256=sha(canonical(inventory)),
            required_labels={'micro_authority'},scope_sha256=scope,inventory_key=inventory_key.public_key(),
            inventory_key_id='inventory',member_key=member_key.public_key(),member_key_id='member')
    assert pins.inspect_reader(reader_for(expected))==expected
    # Correct signatures and immutable versions cannot authorize stale/forged jobs.
    with pytest.raises(ReceiptError):pins.inspect_reader(reader_for({**expected,'jobs_sha256':'f'*64}))


def test_privileged_expected_metadata_is_frozen_after_construction():
    original=metadata();pins=MicroAuthorityPins(original)
    original['authority_version']='MICRO_V4'
    original['life_cycles']=False
    assert pins.metadata['authority_version']=='MICRO_V4_1'
    assert type(pins.metadata['life_cycles']) is int
    with pytest.raises(TypeError):pins.metadata['authority_version']='MICRO_V4'
    with pytest.raises(TypeError):pins.metadata['life_cycles']=False
    with pytest.raises(ReceiptError):pins.verify_metadata(original)
