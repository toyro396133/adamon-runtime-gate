import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.roles.tests import test_receipts as fixtures
from infrastructure.t3.roles.receipts import ReceiptError,seal


def test_role_key_substitution_cannot_make_attacker_receipt_valid():
    fixture=fixtures.Receipts();fixture.setUp();attacker=Ed25519PrivateKey.generate()
    forged=seal(fixture.p,'AUDIT','SYNTHETIC',attacker)
    with pytest.raises(ReceiptError):fixture.v.verify(forged,'AUDIT','dummy')
    with pytest.raises(TypeError):fixture.v.authority.keys[('AUDIT','k')]=attacker.public_key().public_bytes_raw()
    with pytest.raises(TypeError):fixture.v.authority.permit_bindings['p']['case']='attacker'
    with pytest.raises((TypeError,AttributeError)):fixture.v.authority.domains.update(AUDIT='evil')
    with pytest.raises(TypeError):dict.__setitem__(fixture.v.authority.keys,('AUDIT','k'),attacker.public_key().public_bytes_raw())
    with pytest.raises(ReceiptError):fixture.v.verify(forged,'AUDIT','dummy')


def test_caller_key_and_nested_binding_aliases_detached():
    from dataclasses import replace
    fixture=fixtures.Receipts();fixture.setUp();original=fixture.v.authority
    keys=dict(original.keys);bindings={k:dict(v) for k,v in original.permit_bindings.items()}
    candidate=replace(original,keys=keys,permit_bindings=bindings)
    keys.clear();bindings['p']['case']='evil'
    assert candidate.keys==original.keys and candidate.permit_bindings['p']['case']=='dummy'
