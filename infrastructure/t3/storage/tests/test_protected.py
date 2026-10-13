"""Actual local SQLite/AES-GCM/signatures; requester/receipt synthetic, never AWS."""
import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.security.protocol import sign, spki_digest
from infrastructure.t3.storage.evidence import LocalEncryptedStore, StorageFailure, canonical, sha
from infrastructure.t3.storage.chain import InventoryProducer, scope_digest
from infrastructure.t3.storage.attempts import AttemptChain
from infrastructure.t3.storage.broker import NonresearchEvidenceBroker,open_nonresearch_audit,LABELS
from infrastructure.t3.storage.protected import (StorageAccessGate,ScopedNonresearchBroker,
    ScopedInventoryReadback,CAPABILITY_DOMAIN,REQUEST_DOMAIN)

RECEIPT_DOMAIN='ADAMON-NONRESEARCH-VERTICAL-RECEIPT'


class Joined:
    def __init__(self,path):
        self.now=1000
        self.owner=Ed25519PrivateKey.generate();self.channel=Ed25519PrivateKey.generate()
        self.member=Ed25519PrivateKey.generate();self.inventory=Ed25519PrivateKey.generate()
        self.chain_key=Ed25519PrivateKey.generate();self.receipt_key=Ed25519PrivateKey.generate()
        self.binding=dict(source_sha256='a'*64,fixture_sha256='b'*64,role='LIFE',subject_id='canary',job_id=321)
        self.scope=scope_digest('c'*64,'attempt1')
        self.store=LocalEncryptedStore(path/'versions.sqlite',b'x'*32,self.member,'member',storage_scope_sha256=self.scope)
        self.producer=InventoryProducer(self.store,required_labels=LABELS,scope_sha256=self.scope,
            signer=self.inventory,key_id='inventory',member_key=self.member.public_key(),member_key_id='member')
        self.chain=AttemptChain(path/'attempts.sqlite',signer=self.chain_key,key_id='chain')
        self.broker=NonresearchEvidenceBroker(producer=self.producer,chain=self.chain,
            receipt_key=self.receipt_key.public_key(),binding=self.binding,permit_id='permit1',
            campaign_id='canary',attempt_id='attempt1',subject_id='canary',receipt_domain=RECEIPT_DOMAIN)
        self.expected=dict(subject_id='canary',campaign_id='canary',attempt_id='attempt1',
            job_binding_sha256=sha(canonical(self.binding)),permit_id='permit1',source_sha256='a'*64,
            fixture_sha256='b'*64,storage_scope_sha256=self.scope)
        self.gate=StorageAccessGate(path/'requests.sqlite',owner_keys={'owner':self.owner.public_key()},
            expected_binding=self.expected,journal_signer=self.chain_key,journal_key_id='journal',clock=lambda:self.now)
        self.api=ScopedNonresearchBroker(self.broker,self.gate)
        with sqlite3.connect(':memory:') as con:
            con.execute('CREATE TABLE canary(value TEXT)');con.execute("INSERT INTO canary VALUES('NONRESEARCH')")
            self.original=con.serialize()
        self.receipt=sign(dict(version=2,scope='NONRESEARCH_LOCAL_PROCESS_CANARY',status='COMPLETE',phase='COMPLETE',
            reason=None,permit_id='permit1',binding_sha256=sha(canonical(self.binding)),artifact_sha256=sha(self.original),
            artifact_size=len(self.original)),self.receipt_key,'nonresearch-receipt',RECEIPT_DOMAIN)
        self.counter=0
    def capability(self,role='PRODUCER',**updates):
        body=dict(self.expected,version=1,scope='NONRESEARCH_LOCAL_PROCESS_CANARY',capability_id=role.lower()+'1',
            role=role,channel_spki_sha256=spki_digest(self.channel.public_key()),issued_at=1000,expires_at=1100)
        body.update(updates)
        return sign(body,self.owner,'owner',CAPABILITY_DOMAIN)
    def request(self,cap,operation,argument=None,**updates):
        self.counter+=1
        body=dict(version=1,capability_sha256=sha(canonical(cap)),operation=operation,
            argument_sha256=sha(canonical(argument or {})),nonce=f'{self.counter:064x}')
        body.update(updates)
        return sign(body,self.channel,'channel',REQUEST_DOMAIN)
    def seal(self):
        cap=self.capability()
        self.api.start(cap,self.request(cap,'start'),self.channel.public_key())
        arg=dict(receipt_sha256=sha(canonical(self.receipt)),artifact_sha256=sha(self.original),artifact_size_bytes=len(self.original))
        handoff=self.api.preserve(cap,self.request(cap,'preserve',arg),self.channel.public_key(),self.receipt,self.original)
        reader=open_nonresearch_audit(handoff,store=self.store,producer=self.producer,chain_key=self.chain_key.public_key(),
            chain_key_id='chain',**self.broker.trusted_audit_anchor())
        return handoff,reader


def test_actual_joined_encrypted_signed_chain_and_reviewer_readback(tmp_path):
    j=Joined(tmp_path);handoff,reader=j.seal()
    assert j.original not in (tmp_path/'versions.sqlite').read_bytes()
    api=ScopedInventoryReadback(reader,j.gate);cap=j.capability('REVIEWER')
    arg=dict(label='original_artifact',reference=reader.reference('original_artifact'))
    assert api.read_member(cap,j.request(cap,'read_member',arg),j.channel.public_key(),'original_artifact')==j.original
    journal=j.gate.journal();anchor=sha(canonical(journal[-1]))
    assert j.gate.verify_journal(journal,expected_head_sha256=anchor,expected_count=3)['record_count']==3
    assert [e['record']['state'] for e in handoff['attempt_chain']]==['STARTED','SEALED_COMPLETE']
    assert not hasattr(api,'put') and not hasattr(api,'finalize')


@pytest.mark.parametrize('field,value',[
    ('subject_id','foreign'),('campaign_id','foreign'),('attempt_id','foreign'),
    ('job_binding_sha256','d'*64),('permit_id','other'),('source_sha256','d'*64),
    ('fixture_sha256','d'*64),('storage_scope_sha256','d'*64),('channel_spki_sha256','d'*64),
    ('role','AUDITOR'),('scope','RESEARCH'),('expires_at',1000),('issued_at',1001)])
def test_one_signed_authority_mutation_only(tmp_path,field,value):
    j=Joined(tmp_path)
    baseline=j.capability();valid=j.gate.authorize(baseline,j.request(baseline,'start'),j.channel.public_key(),operation='start',argument={})
    assert valid['payload']['operation']=='start'
    bad=sign(dict(baseline['payload'],**{field:value}),j.owner,'owner',CAPABILITY_DOMAIN)
    assert {k for k in bad['payload'] if bad['payload'][k]!=baseline['payload'][k]}=={field}
    with pytest.raises(StorageFailure):j.gate.authorize(bad,j.request(bad,'start'),j.channel.public_key(),operation='start',argument={})
    assert len(j.gate.journal())==1


def test_atomic_request_consumption_and_restart(tmp_path):
    j=Joined(tmp_path);cap=j.capability();req=j.request(cap,'start')
    def consume(_):
        try:j.gate.authorize(cap,req,j.channel.public_key(),operation='start',argument={});return True
        except StorageFailure:return False
    with ThreadPoolExecutor(max_workers=4) as pool:assert sum(pool.map(consume,range(8)))==1
    reopened=StorageAccessGate(tmp_path/'requests.sqlite',owner_keys={'owner':j.owner.public_key()},expected_binding=j.expected,
        journal_signer=j.chain_key,journal_key_id='journal',clock=lambda:1000)
    with pytest.raises(StorageFailure,match='replayed'):reopened.authorize(cap,req,j.channel.public_key(),operation='start',argument={})
    assert len(reopened.journal())==1


def test_revoke_expiry_and_forged_request(tmp_path):
    j=Joined(tmp_path);cap=j.capability()
    req=j.request(cap,'start');bad=copy.deepcopy(req);bad['signature']='00'*64
    with pytest.raises(StorageFailure,match='request'):j.gate.authorize(cap,bad,j.channel.public_key(),operation='start',argument={})
    j.gate.revoke(cap['payload']['capability_id'])
    with pytest.raises(StorageFailure,match='revoked'):j.gate.authorize(cap,req,j.channel.public_key(),operation='start',argument={})
    j.now=1100
    with pytest.raises(StorageFailure,match='expired'):j.gate.authorize(cap,req,j.channel.public_key(),operation='start',argument={})
    assert j.gate.journal()==[]


def test_cross_role_write_and_producer_read_denied(tmp_path):
    j=Joined(tmp_path);cap=j.capability('REVIEWER')
    with pytest.raises(StorageFailure,match='cross-role'):j.api.start(cap,j.request(cap,'start'),j.channel.public_key())
    _,reader=j.seal();cap=j.capability('PRODUCER');api=ScopedInventoryReadback(reader,j.gate)
    arg=dict(label='original_artifact',reference=reader.reference('original_artifact'))
    with pytest.raises(StorageFailure,match='cross-role'):api.read_member(cap,j.request(cap,'read_member',arg),j.channel.public_key(),'original_artifact')


def test_byte_argument_substitution_cannot_write(tmp_path):
    j=Joined(tmp_path);cap=j.capability();j.api.start(cap,j.request(cap,'start'),j.channel.public_key())
    arg=dict(receipt_sha256=sha(canonical(j.receipt)),artifact_sha256=sha(j.original),artifact_size_bytes=len(j.original))
    req=j.request(cap,'preserve',arg)
    with pytest.raises(StorageFailure,match='argument'):j.api.preserve(cap,req,j.channel.public_key(),j.receipt,j.original+b'changed')
    assert len(j.chain.read())==1
    with sqlite3.connect(tmp_path/'versions.sqlite') as con:assert con.execute('SELECT count(*) FROM versions').fetchone()[0]==0


def test_pinned_version_and_local_ciphertext_tamper(tmp_path):
    j=Joined(tmp_path);_,reader=j.seal();member=reader._members['original_artifact']
    with pytest.raises(StorageFailure,match='foreign'):reader.read_version(member.reference.object_id,'wrong-version')
    with sqlite3.connect(tmp_path/'versions.sqlite') as con:
        con.execute('DROP TRIGGER no_update');con.execute('UPDATE versions SET ciphertext=? WHERE object_id=?',(b'truncated',member.reference.object_id))
    with pytest.raises(StorageFailure,match='integrity'):reader.read_member('original_artifact')


def test_signed_journal_truncation_reorder_and_duplicate_attempt(tmp_path):
    j=Joined(tmp_path);j.seal();entries=j.gate.journal();anchor=sha(canonical(entries[-1]))
    with pytest.raises(StorageFailure,match='anchor'):j.gate.verify_journal(entries[:-1],expected_head_sha256=anchor,expected_count=2)
    with pytest.raises(StorageFailure,match='reorder'):j.gate.verify_journal(list(reversed(entries)))
    cap=j.capability()
    with pytest.raises(StorageFailure,match='already'):j.api.start(cap,j.request(cap,'start'),j.channel.public_key())
    assert len(j.chain.read())==2


def test_partial_original_preserved_but_never_complete_audit(tmp_path):
    j=Joined(tmp_path);cap=j.capability();j.api.start(cap,j.request(cap,'start'),j.channel.public_key())
    payload=dict(j.receipt['payload'],status='PARTIAL',phase='GUEST',reason='cancelled',artifact_sha256=None,artifact_size=None)
    receipt=sign(payload,j.receipt_key,'nonresearch-receipt',RECEIPT_DOMAIN)
    arg=dict(receipt_sha256=sha(canonical(receipt)),artifact_sha256=sha(j.original),artifact_size_bytes=len(j.original))
    handoff=j.api.preserve(cap,j.request(cap,'preserve',arg),j.channel.public_key(),receipt,j.original)
    assert handoff['attempt_chain'][-1]['record']['state']=='SEALED_PARTIAL'
    with pytest.raises(StorageFailure,match='partial'):open_nonresearch_audit(handoff,store=j.store,producer=j.producer,
        chain_key=j.chain_key.public_key(),chain_key_id='chain',**j.broker.trusted_audit_anchor())
    assert len(j.store.database.read_bytes())>0


def test_attempt_snapshot_original_bytes_versioned_encrypted_and_retained(tmp_path):
    from infrastructure.t3.storage.snapshots import seal_attempt_snapshot,read_attempt_snapshot
    j=Joined(tmp_path);handoff,_=j.seal();entries=handoff['attempt_chain'];anchor=j.broker.trusted_audit_anchor()
    kwargs=dict(member_key=j.member.public_key(),member_key_id='member',storage_scope_sha256=j.scope,
        chain_key=j.chain_key.public_key(),chain_key_id='chain',expected_head_sha256=anchor['expected_head_sha256'],
        expected_record_count=anchor['expected_record_count'],expected_identity=anchor['expected_identity'])
    snapshot=seal_attempt_snapshot(j.store,entries,**kwargs)
    assert read_attempt_snapshot(snapshot,j.store.read,require_complete=True,**kwargs)==entries
    assert j.store.read(snapshot.evidence)==canonical(entries)
    assert canonical(entries) not in (tmp_path/'versions.sqlite').read_bytes()
    with pytest.raises(StorageFailure,match='anchor'):
        read_attempt_snapshot(replace(snapshot,record_count=1),j.store.read,**kwargs)
    with pytest.raises(StorageFailure,match='create-only'):seal_attempt_snapshot(j.store,entries,**kwargs)


def test_partial_attempt_snapshot_retained_and_never_promoted(tmp_path):
    from infrastructure.t3.storage.snapshots import seal_attempt_snapshot,read_attempt_snapshot
    j=Joined(tmp_path);cap=j.capability();j.api.start(cap,j.request(cap,'start'),j.channel.public_key())
    entries=j.chain.read()
    kwargs=dict(member_key=j.member.public_key(),member_key_id='member',storage_scope_sha256=j.scope,
        chain_key=j.chain_key.public_key(),chain_key_id='chain',expected_head_sha256=sha(canonical(entries[-1])),
        expected_record_count=1,expected_identity=dict(j.broker.identity))
    snapshot=seal_attempt_snapshot(j.store,entries,**kwargs)
    assert read_attempt_snapshot(snapshot,j.store.read,**kwargs)==entries
    with pytest.raises(StorageFailure,match='partial'):read_attempt_snapshot(snapshot,j.store.read,require_complete=True,**kwargs)


def test_capability_expiry_rechecked_after_atomic_lock(tmp_path):
    j=Joined(tmp_path);cap=j.capability();req=j.request(cap,'start')
    values=iter([1000,1100])
    j.gate.clock=lambda:next(values)
    with pytest.raises(StorageFailure,match='expired'):j.gate.authorize(cap,req,j.channel.public_key(),operation='start',argument={})
    assert j.gate.journal()==[]


def test_owner_trust_and_expected_binding_are_constructor_snapshots(tmp_path):
    j=Joined(tmp_path);owners={'owner':j.owner.public_key()};expected=dict(j.expected)
    gate=StorageAccessGate(tmp_path/'snapshot-trust.sqlite',owner_keys=owners,expected_binding=expected,
        journal_signer=j.chain_key,journal_key_id='journal',clock=lambda:1000)
    owners['owner']=Ed25519PrivateKey.generate().public_key();expected['permit_id']='attacker'
    cap=j.capability();req=j.request(cap,'start')
    assert gate.authorize(cap,req,j.channel.public_key(),operation='start',argument={})['payload']['operation']=='start'
