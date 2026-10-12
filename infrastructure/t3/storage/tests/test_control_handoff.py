"""Synthetic closed registries, actual encrypted bytes; no controls executed."""
from dataclasses import asdict
import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.evidence import LocalEncryptedStore, StorageFailure, canonical, sha
from infrastructure.t3.storage.chain import InventoryProducer,SignedInventoryReader,scope_digest
from infrastructure.t3.storage.control_handoff import COUNTS,verify_control_bytes


def configured(tmp_path,mutation=None):
    key=Ed25519PrivateKey.generate();invkey=Ed25519PrivateKey.generate();scope=scope_digest('a'*64,'attempt1')
    store=LocalEncryptedStore(tmp_path/'encrypted.sqlite',os.urandom(32),key,'member',storage_scope_sha256=scope)
    subjects={group:tuple(group+str(i) for i in range(count)) for group,count in COUNTS.items()}
    members={};manifest={group:{} for group in COUNTS}
    def ref(envelope,kind,subject):
        x=asdict(envelope.reference);x['bytes']=x.pop('size_bytes');return dict(x,kind=kind,subject=subject)
    for group,items in subjects.items():
        for subject in items:
            member=store.put(('explicit-synthetic-'+subject).encode());members[subject]=member
            manifest[group][subject]=ref(member,group,subject)
    if mutation:mutation(manifest)
    member=store.put(canonical(manifest));members['manifest']=member
    from infrastructure.t3.storage.inventory import create_inventory
    inventory=create_inventory(members,state='SEALED_COMPLETE',signer=invkey,key_id='inventory',trusted_member_key=key.public_key(),trusted_member_key_id='member')
    reader=SignedInventoryReader(store,inventory,inventory_sha256=sha(canonical(inventory)),required_labels=members,
        scope_sha256=scope,inventory_key=invkey.public_key(),inventory_key_id='inventory',member_key=key.public_key(),member_key_id='member')
    return dict(manifest_reference=ref(member,'control_inventory','CONTROL_INVENTORY'),registered_subjects=subjects,immutable_reader=reader)


def test_signed_exact_versions_verify_bytes_without_control_completion(tmp_path):
    result=verify_control_bytes(**configured(tmp_path))
    assert result['scope']=='BYTE_VERIFIED_NOT_SEMANTIC_CONTROL_COMPLETION'
    assert result['can_close_gate'] is False and len(result['verified'])==49


@pytest.mark.parametrize('mutation',[
    lambda m:m['offline'].pop('offline0'),
    lambda m:m['offline']['offline0'].update(version_id='latest'),
    lambda m:m['corruption']['corruption0'].update(kind='offline'),
    lambda m:m['corruption']['corruption0'].update(subject='foreign'),
    lambda m:m['offline']['offline1'].update(object_id=m['offline']['offline0']['object_id'],sha256=m['offline']['offline0']['sha256'],version_id=m['offline']['offline0']['version_id']),
    lambda m:m['micro']['micro0'].update(version_id='missing-version'),
])
def test_signed_manifest_shape_cannot_hide_missing_original_or_alias(tmp_path,mutation):
    with pytest.raises(StorageFailure):verify_control_bytes(**configured(tmp_path,mutation))
