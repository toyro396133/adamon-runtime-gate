"""Closed nonresearch completion -> sealed bytes -> append-only audit handoff.

No science, caller paths, shell or overall PASS. Store can be local encrypted
SQLite or an independently configured S3 adapter. Local scope is not ObjectLock.
"""
from .evidence import StorageFailure, canonical, sha, HEX
import json
from .attempts import verify_chain
from .chain import SignedInventoryReader
from ..security.protocol import verify, digest

LABELS = frozenset({'completion_receipt', 'original_artifact'})


class NonresearchEvidenceBroker:
    """One-shot trusted owner broker; immutable exact registered bytes only."""
    def __init__(self, *, producer, chain, receipt_key, binding, permit_id,
                 campaign_id, attempt_id, subject_id, receipt_domain):
        if producer.labels != LABELS:
            raise StorageFailure('closed nonresearch artifact registry')
        self.producer, self.chain, self.key = producer, chain, receipt_key
        self.binding, self.permit_id = dict(binding), permit_id
        self.domain = receipt_domain
        self.identity = dict(campaign_id=campaign_id, attempt_id=attempt_id,
                             subject_id=subject_id, source_sha256=binding['source_sha256'])
        self.started = False
        self.finished = False
        self.head = None
        self._audit_anchor = None

    def start(self):
        if self.started:
            raise StorageFailure('attempt already started')
        entry = self.chain.append(dict(self.identity, state='STARTED', inventory_sha256=None))
        self.started = True
        self.head = sha(canonical(entry))
        return entry

    def preserve(self, receipt, original_artifact):
        if not self.started or self.finished:
            raise StorageFailure('one-shot started attempt required')
        if type(original_artifact) is not bytes or not original_artifact:
            raise StorageFailure('missing original artifact; cannot regenerate')
        payload = verify(receipt, {'nonresearch-receipt': self.key}, self.domain)
        expected = {'version', 'scope', 'status', 'phase', 'reason', 'permit_id', 'binding_sha256', 'artifact_sha256', 'artifact_size'}
        if (set(payload) != expected or type(payload['version']) is not int or payload['version'] != 2
            or payload['scope'] != 'NONRESEARCH_LOCAL_PROCESS_CANARY'
            or payload['status'] not in {'COMPLETE', 'PARTIAL'}
            or payload['permit_id'] != self.permit_id or payload['binding_sha256'] != digest(self.binding)):
            raise StorageFailure('untrusted completion identity/scope/status')
        state = 'SEALED_COMPLETE' if payload['status'] == 'COMPLETE' else 'SEALED_PARTIAL'
        if state == 'SEALED_COMPLETE' and payload['phase'] != 'COMPLETE':
            raise StorageFailure('incomplete phase cannot seal complete')
        if state == 'SEALED_COMPLETE' and (payload['artifact_sha256'] != sha(original_artifact)
            or type(payload['artifact_size']) is not int or payload['artifact_size'] != len(original_artifact)):
            raise StorageFailure('signed guest artifact byte binding mismatch')
        # Verify and pin retained head before any sealing; append compares again
        # under BEGIN IMMEDIATE to close competing terminal-record races.
        entries = self.chain.read()
        if sha(canonical(entries[-1])) != self.head:
            raise StorageFailure('stale attempt head; preserve original source')
        inventory = self.producer.seal({'completion_receipt': canonical(receipt),
                                       'original_artifact': original_artifact}, state=state)
        entry = self.chain.append(dict(self.identity, state=state,
            inventory_sha256=sha(canonical(inventory))), expected_head_sha256=self.head)
        self.finished = True
        entries = self.chain.read()
        head = sha(canonical(entry))
        chain_summary = verify_chain(entries, self.chain.signer.public_key(), self.chain.key_id,
            expected_head_sha256=head, expected_record_count=len(entries))
        self._audit_anchor = dict(expected_head_sha256=head,expected_record_count=len(entries),expected_identity=dict(self.identity),
            expected_binding_sha256=digest(self.binding),expected_permit_id=self.permit_id,receipt_key=self.key,receipt_domain=self.domain)
        return dict(scope='NONRESEARCH_EVIDENCE_HANDOFF', inventory=inventory,
                    attempt_chain=entries, chain_summary=chain_summary)

    def trusted_audit_anchor(self):
        if self._audit_anchor is None:raise StorageFailure('terminal owner audit anchor absent')
        return dict(self._audit_anchor,expected_identity=dict(self.identity))


def open_nonresearch_audit(handoff, *, store, producer, chain_key, chain_key_id, expected_head_sha256, expected_record_count, expected_identity, expected_binding_sha256, expected_permit_id, receipt_key, receipt_domain):
    """Immutable pinned read capability only. No caller PASS/gates accepted."""
    if type(handoff) is not dict or set(handoff) != {'scope','inventory','attempt_chain','chain_summary'} or handoff['scope'] != 'NONRESEARCH_EVIDENCE_HANDOFF':
        raise StorageFailure('closed nonresearch handoff')
    if (type(expected_head_sha256) is not str or not HEX.fullmatch(expected_head_sha256)
        or type(expected_record_count) is not int or expected_record_count<2):
        raise StorageFailure('authenticated nonempty chain head/count required')
    if type(expected_identity) is not dict or set(expected_identity)!={'campaign_id','attempt_id','subject_id','source_sha256'}:
        raise StorageFailure('owner-retained exact audit identity required')
    summary = handoff['chain_summary']
    if (summary.get('head_sha256')!=expected_head_sha256 or summary.get('record_count')!=expected_record_count):
        raise StorageFailure('untrusted transport cannot choose chain anchor')
    verify_chain(handoff['attempt_chain'], chain_key, chain_key_id,
        expected_head_sha256=expected_head_sha256, expected_record_count=expected_record_count)
    terminal = handoff['attempt_chain'][-1]['record']
    if any(terminal.get(k)!=v for k,v in expected_identity.items()):
        raise StorageFailure('terminal campaign/attempt/subject/source mismatch')
    if terminal['state'] != 'SEALED_COMPLETE' or terminal['inventory_sha256'] != sha(canonical(handoff['inventory'])):
        raise StorageFailure('partial/missing inventory cannot qualify audit')
    reader = SignedInventoryReader(store, handoff['inventory'],
        inventory_sha256=terminal['inventory_sha256'], required_labels=LABELS,
        scope_sha256=producer.scope, inventory_key=producer.signer.public_key(),
        inventory_key_id=producer.key_id, member_key=producer.member_key,
        member_key_id=producer.member_key_id)

    if type(expected_binding_sha256) is not str or not HEX.fullmatch(expected_binding_sha256) or type(expected_permit_id) is not str or not expected_permit_id:
        raise StorageFailure('owner-retained job/role/subject/code binding required')
    try:
        envelope=json.loads(reader.read_member('completion_receipt'))
        completion=verify(envelope,{'nonresearch-receipt':receipt_key},receipt_domain)
    except Exception as exc:
        raise StorageFailure('untrusted retained completion receipt') from exc
    if (completion.get('scope')!='NONRESEARCH_LOCAL_PROCESS_CANARY' or completion.get('status')!='COMPLETE'
        or completion.get('phase')!='COMPLETE' or completion.get('binding_sha256')!=expected_binding_sha256
        or completion.get('permit_id')!=expected_permit_id):
        raise StorageFailure('completion Job/role/subject/source/fixture/permit mismatch')
    original=reader.read_member('original_artifact')
    if (completion.get('version')!=2 or completion.get('artifact_sha256')!=sha(original)
        or type(completion.get('artifact_size')) is not int or completion['artifact_size']!=len(original)):
        raise StorageFailure('retained artifact byte binding mismatch')
    return reader
