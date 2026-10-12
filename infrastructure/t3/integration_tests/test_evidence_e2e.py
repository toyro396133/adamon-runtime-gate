"""Actual local Guest process -> crypto/SQLite storage -> pinned readonly Audit.

REST allocation remains explicit synthetic. No S3/KVM/science/overall PASS.
"""
import copy
import os
import sqlite3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.integration_tests.test_vertical_nonresearch import setup
from infrastructure.t3.runtime.vertical import RECEIPT_DOMAIN
from infrastructure.t3.storage.evidence import LocalEncryptedStore, StorageFailure, sha, canonical
from infrastructure.t3.storage.chain import InventoryProducer, scope_digest
from infrastructure.t3.storage.attempts import AttemptChain
from infrastructure.t3.storage.broker import NonresearchEvidenceBroker, open_nonresearch_audit, LABELS
from infrastructure.t3.security.protocol import Denied


def configured(tmp_path, setup):
    member=Ed25519PrivateKey.generate();inventory=Ed25519PrivateKey.generate();chain_key=Ed25519PrivateKey.generate()
    scope=scope_digest('a'*64,'attempt1')
    store=LocalEncryptedStore(tmp_path/'encrypted.db',os.urandom(32),member,'member',storage_scope_sha256=scope)
    producer=InventoryProducer(store,required_labels=LABELS,scope_sha256=scope,
        signer=inventory,key_id='inventory',member_key=member.public_key(),member_key_id='member')
    chain=AttemptChain(tmp_path/'attempts.db',signer=chain_key,key_id='chain')
    broker=NonresearchEvidenceBroker(producer=producer,chain=chain,receipt_key=setup['receipt'].public_key(),
        binding=setup['binding'],permit_id='nonresearch-only',campaign_id='campaign1',attempt_id='attempt1',
        subject_id='nonresearch1',receipt_domain=RECEIPT_DOMAIN)
    return store,producer,chain,broker


def artifact():
    c=sqlite3.connect(':memory:')
    try:
        c.execute('CREATE TABLE canary(value TEXT)');c.execute('INSERT INTO canary VALUES(?)',('nonresearch',));c.commit()
        return c.serialize()
    finally:c.close()


def test_real_completion_encrypted_sqlite_append_chain_readonly_audit(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run();original=result['artifact_bytes'];digest=sha(original)
    handoff=broker.preserve(result['receipt'],original)
    reader=open_nonresearch_audit(handoff,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**broker.trusted_audit_anchor())
    data=reader.read_member('original_artifact');assert sha(data)==digest
    audit=tmp_path/'audit.db';audit.write_bytes(data)
    c=sqlite3.connect(f'file:{audit}?mode=ro&immutable=1',uri=True)
    try:
        c.execute('PRAGMA query_only=ON')
        assert c.execute('PRAGMA integrity_check').fetchone()==('ok',)
        assert c.execute('SELECT value FROM canary').fetchall()==[('nonresearch',)]
        with pytest.raises(sqlite3.OperationalError):c.execute('DELETE FROM canary')
    finally:c.close()
    assert sha(audit.read_bytes())==digest and sha(original)==digest
    assert handoff['scope']=='NONRESEARCH_EVIDENCE_HANDOFF' and 'PASS' not in canonical(handoff).decode()
    assert len(chain.read())==2
    assert not hasattr(reader,'put')
    with pytest.raises(StorageFailure,match='one-shot'):broker.preserve(result['receipt'],original)
    with pytest.raises(StorageFailure):store.put(original)
    altered=copy.deepcopy(handoff);altered['inventory']['members'].pop()
    with pytest.raises(StorageFailure):open_nonresearch_audit(altered,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**broker.trusted_audit_anchor())


def test_actual_cancelled_guest_preserves_partial_without_audit_success(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    controller=setup['controller']()
    with pytest.raises(Denied):controller.run(cancelled=lambda:True)
    assert controller.child.exitcode==-9
    handoff=broker.preserve(setup['partial'][0],b'original-partial-canary')
    assert handoff['attempt_chain'][-1]['record']['state']=='SEALED_PARTIAL'
    with pytest.raises(StorageFailure,match='partial'):open_nonresearch_audit(handoff,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**broker.trusted_audit_anchor())
    assert len(chain.read())==2


def test_missing_original_and_changed_binding_cannot_seal(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run()
    with pytest.raises(StorageFailure,match='missing original'):broker.preserve(result['receipt'],b'')
    broker.binding['run_attempt']+=1
    with pytest.raises(StorageFailure,match='identity'):broker.preserve(result['receipt'],result['artifact_bytes'])
    assert len(chain.read())==1


def test_competing_terminal_append_rejects_stale_head_atomically(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run()
    chain.append(dict(broker.identity,state='SEALED_PARTIAL',inventory_sha256='b'*64),expected_head_sha256=broker.head)
    with pytest.raises(StorageFailure,match='stale'):broker.preserve(result['receipt'],result['artifact_bytes'])
    with pytest.raises(StorageFailure,match='stale'):chain.append(dict(broker.identity,state='SEALED_COMPLETE',inventory_sha256='c'*64),expected_head_sha256=broker.head)
    assert len(chain.read())==2


def test_attacker_recalculated_summary_cannot_choose_audit_anchor(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run();handoff=broker.preserve(result['receipt'],result['artifact_bytes'])
    altered=copy.deepcopy(handoff);altered['chain_summary']['record_count']=1
    altered['chain_summary']['head_sha256']=sha(canonical(altered['attempt_chain'][0]))
    altered['attempt_chain']=altered['attempt_chain'][:1]
    with pytest.raises(StorageFailure,match='anchor'):
        open_nonresearch_audit(altered,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**broker.trusted_audit_anchor())
    anchor=broker.trusted_audit_anchor();anchor['expected_identity']['attempt_id']='other-attempt'
    with pytest.raises(StorageFailure,match='terminal'):
        open_nonresearch_audit(handoff,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**anchor)


@pytest.mark.parametrize('field,value',[('expected_binding_sha256','f'*64),('expected_permit_id','foreign-permit'),('receipt_key',Ed25519PrivateKey.generate().public_key())])
def test_retained_audit_binding_cannot_use_foreign_job_or_owner(tmp_path,setup,field,value):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run();handoff=broker.preserve(result['receipt'],result['artifact_bytes'])
    anchor=broker.trusted_audit_anchor();anchor[field]=value
    with pytest.raises(StorageFailure):
        open_nonresearch_audit(handoff,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**anchor)


@pytest.mark.parametrize('mutation',[lambda entries:entries.reverse(),lambda entries:entries.append(entries[-1])])
def test_reordered_or_duplicate_signed_chain_rejected_with_owner_anchor(tmp_path,setup,mutation):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run();handoff=broker.preserve(result['receipt'],result['artifact_bytes'])
    altered=copy.deepcopy(handoff);mutation(altered['attempt_chain'])
    with pytest.raises(StorageFailure):
        open_nonresearch_audit(altered,store=store,producer=producer,chain_key=chain.signer.public_key(),chain_key_id='chain',**broker.trusted_audit_anchor())


def test_owner_cannot_substitute_artifact_after_guest_completion(tmp_path,setup):
    store,producer,chain,broker=configured(tmp_path,setup);broker.start()
    result=setup['controller']().run()
    with pytest.raises(StorageFailure,match='byte binding'):
        broker.preserve(result['receipt'],result['artifact_bytes']+b'changed')
    assert len(chain.read())==1 and not broker.finished


@pytest.mark.parametrize('replacement',[{'version':4,'artifact_hex':'00'}, {'version':4,'artifact_hex':'zz'}])
def test_corrupted_export_kills_real_guest_and_retains_partial(setup,monkeypatch,replacement):
    # Fault injected only into the host export transport; Guest is a real child.
    from infrastructure.t3.runtime import vertical
    monkeypatch.setattr(vertical,'receive',lambda stream:replacement)
    controller=setup['controller']()
    with pytest.raises(Denied,match='artifact'):
        controller.run()
    assert controller.child.exitcode==-9
    assert setup['partial'][-1]['payload']['status']=='PARTIAL'
    assert setup['partial'][-1]['payload']['artifact_sha256'] is None


def test_cancelled_permit_cannot_be_reused_for_new_guest(setup):
    first=setup['controller']()
    with pytest.raises(Denied):first.run(cancelled=lambda:True)
    second=setup['controller']()
    with pytest.raises(Denied,match='not issued'):second.run()
    assert second.child is None and first.child.exitcode==-9
