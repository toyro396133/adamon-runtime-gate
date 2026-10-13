"""One joined canary: assignment -> real child -> original bytes -> Audit -> AND.

Scope is SYNTHETIC_INTEGRATION_TESTED + LOCAL_OS_TESTED only. GitHub REST and
Runner assignment are synthetic; Worker/Guest/pidfd/SCM_RIGHTS/crypto/SQLite are
real. No Runner full build, microVM, distinct UID jail, KVM, AWS or live Job is
claimed. The closed 27/2/23/12 registry has synthetic subjects/assertions; its
first LIFE subject explicitly maps to the compiled NONRESEARCH_SOCKET_CANARY.
All other members use registered synthetic bytes, not research histories.
Accepted IMP001 helper is reused unchanged, never re-reviewed here.
"""
import copy
import hashlib
import json
import sqlite3
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.t3.integration_tests.test_vertical_nonresearch import setup as runtime_setup
from infrastructure.t3.integration_tests.test_evidence_e2e import configured
from infrastructure.t3.roles.tests.test_micro_audit_aggregation_integration import SyntheticCampaign, digest
from infrastructure.t3.roles.receipts import ReceiptError, canonical
from infrastructure.t3.runtime.vertical import SUBJECT, RECEIPT_DOMAIN
from infrastructure.t3.runtime.microvm import Blocked
from infrastructure.t3.security.protocol import Denied, verify, sign, spki_digest
from infrastructure.t3.storage.broker import open_nonresearch_audit
from infrastructure.t3.storage.evidence import StorageFailure, sha
from infrastructure.t3.storage.protected import StorageAccessGate, ScopedNonresearchBroker, ScopedInventoryReadback, CAPABILITY_DOMAIN, REQUEST_DOMAIN


class UnifiedCampaign(SyntheticCampaign):
    """Owner-built synthetic role registry with one actual canary byte producer."""
    def __init__(self, directory, runtime, result, reader):
        self.connected=False
        self.runtime=runtime;self.result=result;self.original_reader=reader
        # This is the only mapping; no arbitrary workflow subject/path selector.
        self.subject_mapping={'synthetic_life_0':SUBJECT}
        super().__init__(directory)
        subject=self.life[0]
        assert self.subject_mapping=={subject:runtime['binding']['subject']}
        original=reader.read_member('original_artifact')
        completion=reader.read_member('completion_receipt')
        assert original==result['artifact_bytes']
        assert completion==canonical(result['receipt'])
        self.members[subject]={'artifact':self.store.put(original),
            'runtime_completion':self.store.put(completion),
            'runtime_binding':self.store.put(canonical(runtime['binding']))}
        inventory=self.inventory(self.members[subject]);self.inventories[subject]=inventory
        producer=self.sign(dict(self.payloads[('LIFE',subject)],inventory_sha256=digest(inventory)))
        self.connected=True
        manifest=self.audit.inspect(producer,inventory)
        self.manifests[subject]=manifest
        sealed=self.audit.seal_manifest(manifest,store=self.store);self.sealed_manifests[subject]=sealed
        audit=self.sign(dict(self.payloads[('AUDIT',subject)],audit_manifest=asdict(sealed.reference)))
        for index,envelope in enumerate(self.receipts):
            payload=envelope['payload']
            if payload.get('case')==subject:
                self.receipts[index]=producer if payload['role']=='LIFE' else audit

    def reader_factory(self,payload,inventory):
        subject=payload.get('case',payload.get('control_id'))
        if self.connected and subject==self.life[0]:
            return self.reader(inventory,{'artifact','runtime_completion','runtime_binding'},payload['inventory_sha256'])
        return super().reader_factory(payload,inventory)

    def evaluator(self,subject,reader):
        if not self.connected or subject!=self.life[0]:return super().evaluator(subject,reader)
        original=reader.read_member('artifact')
        assert original==self.original_reader.read_member('original_artifact')==self.result['artifact_bytes']
        completion=json.loads(reader.read_member('runtime_completion'))
        assert completion==self.result['receipt']
        payload=verify(completion,{'nonresearch-receipt':self.runtime['receipt'].public_key()},RECEIPT_DOMAIN)
        binding=json.loads(reader.read_member('runtime_binding'))
        assert binding==self.runtime['binding'] and binding['subject']==self.subject_mapping[subject]
        assert payload['binding_sha256']==digest(binding) and payload['permit_id']=='nonresearch-only'
        assert payload['status']=='COMPLETE' and payload['artifact_sha256']==sha(original)
        assert payload['artifact_size']==len(original)
        # Deserialize original Guest bytes into query-only SQLite, never generate
        # a replacement history. Original encrypted version remains unchanged.
        connection=sqlite3.connect(':memory:')
        try:
            connection.deserialize(original);connection.execute('PRAGMA query_only=ON')
            assert connection.execute('PRAGMA integrity_check').fetchone()==('ok',)
            assert connection.execute('SELECT value FROM canary').fetchall()==[('nonresearch',)]
            with pytest.raises(sqlite3.OperationalError):connection.execute('DELETE FROM canary')
        finally:connection.close()
        self.evaluator_calls.append(subject)
        return dict(gates={g:dict(self.registry.gate_assertions[g]) for g in self.gates},
            controls={},failures=0,errors=0,skips=0)


class Joined:
    def __init__(self,directory,runtime):
        self.directory=directory;self.runtime=runtime
        self.store,self.producer,self.chain,self.broker=configured(directory,runtime)
        self.storage_owner=Ed25519PrivateKey.generate()
        self.channels={r:Ed25519PrivateKey.generate() for r in ('PRODUCER','AUDITOR','REVIEWER')}
        binding=dict(subject_id=self.broker.identity['subject_id'],campaign_id=self.broker.identity['campaign_id'],
            attempt_id=self.broker.identity['attempt_id'],job_binding_sha256=digest(runtime['binding']),
            permit_id=self.broker.permit_id,source_sha256=runtime['binding']['source_sha256'],
            fixture_sha256=runtime['binding']['fixture_sha256'],storage_scope_sha256=self.producer.scope)
        self.storage_gate=StorageAccessGate(directory/'access.sqlite',owner_keys={'owner':self.storage_owner.public_key()},
            expected_binding=binding,journal_signer=Ed25519PrivateKey.generate(),journal_key_id='journal',clock=lambda:110)
        self.capabilities={role:sign(dict(binding,version=1,scope='NONRESEARCH_LOCAL_PROCESS_CANARY',
            capability_id='cap_'+role,role=role,channel_spki_sha256=spki_digest(key.public_key()),issued_at=100,expires_at=200),
            self.storage_owner,'owner',CAPABILITY_DOMAIN) for role,key in self.channels.items()}
        self.nonce=0;self.scoped=ScopedNonresearchBroker(self.broker,self.storage_gate)
        self.scoped.start(*self.authorization('PRODUCER','start',{}));self.controller=runtime['controller']()
        self.result=None;self.handoff=None;self.campaign=None

    def authorization(self,role,operation,argument):
        self.nonce+=1;cap=self.capabilities[role];key=self.channels[role]
        request=sign(dict(version=1,capability_sha256=sha(canonical(cap)),operation=operation,
            argument_sha256=sha(canonical(argument)),nonce=f'{self.nonce:064x}'),key,'channel',REQUEST_DOMAIN)
        return cap,request,key.public_key()

    def preserve(self,receipt,artifact):
        argument=dict(receipt_sha256=sha(canonical(receipt)),artifact_sha256=sha(artifact),artifact_size_bytes=len(artifact))
        return self.scoped.preserve(*self.authorization('PRODUCER','preserve',argument),receipt,artifact)

    def complete(self):
        self.result=self.controller.run()
        self.handoff=self.preserve(self.result['receipt'],self.result['artifact_bytes'])
        reader=self.readback()
        self.campaign=UnifiedCampaign(self.directory,self.runtime,self.result,reader)
        assert self.campaign.valid()
        assert self.controller.child.exitcode==0 and len(self.chain.read())==2
        return self

    def readback(self,handoff=None):
        reader=open_nonresearch_audit(self.handoff if handoff is None else handoff,
            store=self.store,producer=self.producer,chain_key=self.chain.signer.public_key(),
            chain_key_id='chain',**self.broker.trusted_audit_anchor())
        scoped=ScopedInventoryReadback(reader,self.storage_gate)
        for role in ('AUDITOR','REVIEWER'):
            for label in ('original_artifact','completion_receipt'):
                argument=dict(label=label,reference=reader.reference(label))
                assert scoped.read_member(*self.authorization(role,'read_member',argument),label)==reader.read_member(label)
        return reader

    def partial(self):
        assert self.runtime['partial'][-1]['payload']['status']=='PARTIAL'
        handoff=self.preserve(self.runtime['partial'][-1],b'NONRESEARCH_PARTIAL_ONLY')
        assert handoff['attempt_chain'][-1]['record']['state']=='SEALED_PARTIAL'
        with pytest.raises(StorageFailure,match='partial'):self.readback(handoff)
        assert self.campaign is None
        return handoff


@pytest.fixture
def joined_factory(tmp_path):
    generators=[];instances=[];counter=0
    def factory():
        nonlocal counter
        directory=tmp_path/str(counter);directory.mkdir();counter+=1
        generator=runtime_setup.__wrapped__(directory);generators.append(generator)
        joined=Joined(directory,next(generator));instances.append(joined);return joined
    yield factory
    witnesses=[]
    for joined in instances:
        witnesses.append(dict(phase=joined.controller.phase,
            child_exitcode=None if joined.controller.child is None else joined.controller.child.exitcode,
            original_sha256=None if joined.result is None else sha(joined.result['artifact_bytes']),
            completion_receipt_sha256=None if joined.result is None else digest(joined.result['receipt']),
            signed_partial_sha256=[digest(r) for r in joined.runtime['partial']],
            inventory_sha256=None if joined.handoff is None else digest(joined.handoff['inventory']),
            attempt_chain_sha256=digest(joined.chain.read()),
            authenticated_storage_operations=len(joined.storage_gate.journal()),
            synthetic_aggregation_evaluated=joined.campaign is not None))
    (tmp_path/'unified_witness.json').write_text(json.dumps(dict(
        scope='NONRESEARCH_UNIFIED_INTEGRATION',levels=['SYNTHETIC_INTEGRATION_TESTED','LOCAL_OS_TESTED'],
        real=['owned_Worker','owned_Guest','pidfd','SO_PEERCRED','sealed_memfd','Ed25519','AES_GCM',
              'signed_inventory','SQLite','EvidenceAudit.inspect','Aggregator.evaluate'],
        synthetic=['REST_assignment','Runner_identity','registry_subjects','gate_assertions',
                   'Supervisor_death_propagation','watchdog_cgroup_fd'],
        live_runtime_verified=False,research_run=False,terminal_pass_signed=False,witnesses=witnesses),indent=2)+'\n')
    for generator in reversed(generators):
        try:next(generator)
        except StopIteration:pass


def test_unified_positive_original_guest_bytes_signed_audit_full_and_no_terminal_pass(joined_factory):
    joined=joined_factory().complete();campaign=joined.campaign
    assert len(campaign.receipts)==58
    assert (len(campaign.life),len(campaign.micro),len(campaign.gates),len(campaign.controls))==(27,2,23,12)
    assert campaign.aggregator().evaluate(campaign.receipts)=={'overall_pass':True}
    with pytest.raises(ReceiptError,match='PASS_TOTAL signing disabled'):
        campaign.aggregator().finalize(campaign.receipts,{},Ed25519PrivateKey.generate(),None)
    dispatch=joined.runtime['supervisor'].dispatch
    with pytest.raises(Denied,match='NO_APPROVED_EXECUTION_FREEZE'):
        joined.runtime['message']('WORKER','fixed_step_execute',dict(assignment_sha256=dispatch.sha256,step_id=dispatch.assignment['step_id']))


@pytest.mark.parametrize('fault',['invalid_authority','invalid_source','invalid_permit','startup_failure','cancellation','worker_death','supervisor_death','cross_role'])
def test_unified_runtime_faults_preserve_signed_partial_and_prevent_audit(joined_factory,monkeypatch,fault):
    joined_factory().complete()  # Entire unaffected chain passes before mutation.
    joined=joined_factory();runtime=joined.runtime
    if fault=='invalid_authority':
        runtime['supervisor'].dispatch.authorized=False
    elif fault=='invalid_source':
        import infrastructure.t3.runtime.vertical as vertical
        monkeypatch.setattr(vertical,'SOURCE',b'injected wrong pinned bytes')
    elif fault=='invalid_permit':
        # Consume the authentic permit first, keeping receipt identity intact.
        runtime['ledger'].consume('nonresearch-only',runtime['binding'],'competing-session')
    elif fault=='startup_failure':
        import infrastructure.t3.runtime.vertical as vertical
        def fail(_):raise OSError('injected retained birth failure')
        monkeypatch.setattr(vertical,'owned_record',fail)
    elif fault=='worker_death':
        runtime['worker'].kill();runtime['worker'].wait()
    elif fault=='supervisor_death':
        # The independent watchdog actually kills a retained descendant after
        # an isolated owner process dies. Its cgroup fd is explicitly synthetic.
        # The in-test Supervisor is not killed with pytest; revocation is the
        # synthetic propagation of that observed owner death into this chain.
        from infrastructure.t3.integration_tests.test_vertical_nonresearch import test_independent_watchdog_supervisor_death_kills_real_owned_descendant
        test_independent_watchdog_supervisor_death_kills_real_owned_descendant(joined.directory)
        runtime['supervisor'].dispatch.revoked=True
    elif fault=='cross_role':
        import infrastructure.t3.runtime.vertical as vertical
        original=vertical.issue
        def wrong_role(binding,*args):return original(dict(binding,role='AUDIT'),*args)
        monkeypatch.setattr(vertical,'issue',wrong_role)
    with pytest.raises((Denied,OSError,Blocked)):
        joined.controller.run(cancelled=(lambda:True) if fault=='cancellation' else (lambda:False))
    if joined.controller.child is not None:assert not joined.controller.child.is_alive()
    joined.partial()
    assert joined.result is None


@pytest.mark.parametrize('fault',['storage_corruption','duplicate_attempt','audit_mismatch','missing_gate','cross_role_receipt','cross_role_storage'])
def test_unified_postcompletion_faults_rejected_after_complete_baseline(joined_factory,fault):
    joined=joined_factory().complete();campaign=joined.campaign
    assert campaign.valid()
    if fault=='storage_corruption':
        original=next(m for m in joined.handoff['inventory']['members'] if m['label']=='original_artifact')
        # Explicit privileged adversary bypasses local immutable trigger: this
        # demonstrates detection, not OS/S3 administrator immutability.
        with joined.store._connect() as connection:
            connection.execute('DROP TRIGGER no_update')
            connection.execute('UPDATE versions SET ciphertext=? WHERE object_id=?',(b'corrupted',original['evidence']['reference']['object_id']))
        with pytest.raises(StorageFailure):joined.readback().read_member('original_artifact')
    elif fault=='duplicate_attempt':
        before=joined.chain.read()
        with pytest.raises(StorageFailure,match='one-shot'):
            joined.preserve(joined.result['receipt'],joined.result['artifact_bytes'])
        assert joined.chain.read()==before
    elif fault=='cross_role_receipt':
        receipts=copy.deepcopy(campaign.receipts)
        producer=next(i for i,e in enumerate(receipts) if e['payload'].get('case')==campaign.life[0] and e['payload']['role']=='LIFE')
        receipts[producer]['payload']['role']='AUDIT'
        with pytest.raises(ReceiptError):campaign.aggregator().evaluate(receipts)
    elif fault=='cross_role_storage':
        argument=dict(receipt_sha256=sha(canonical(joined.result['receipt'])),
            artifact_sha256=sha(joined.result['artifact_bytes']),artifact_size_bytes=len(joined.result['artifact_bytes']))
        before=len(joined.storage_gate.journal())
        with pytest.raises(StorageFailure,match='cross-role storage operation denied'):
            joined.scoped.preserve(*joined.authorization('AUDITOR','preserve',argument),
                joined.result['receipt'],joined.result['artifact_bytes'])
        assert len(joined.storage_gate.journal())==before
    else:
        subject=campaign.life[0];manifest=copy.deepcopy(campaign.manifests[subject])
        if fault=='audit_mismatch':manifest['producer_receipt_sha256']='0'*64
        else:manifest['gates'].pop(campaign.gates[-1])
        sealed=campaign.store.put(canonical(manifest));campaign.sealed_manifests[subject]=sealed
        receipts=copy.deepcopy(campaign.receipts)
        for index,envelope in enumerate(receipts):
            payload=envelope['payload']
            if payload.get('case')==subject and payload['role']=='AUDIT':
                receipts[index]=campaign.sign(dict(payload,audit_manifest=asdict(sealed.reference)))
        reason='audit producer mismatch' if fault=='audit_mismatch' else 'missing/unexpected gate/control'
        with pytest.raises(ReceiptError,match=reason):campaign.aggregator().evaluate(receipts)
