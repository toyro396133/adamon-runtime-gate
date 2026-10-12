"""Immutable exact-version snapshots of original signed attempt records.

The snapshot is byte sealing, never replacement/reconstruction of history. Its
head/count are always compared with an independently retained owner anchor.
Partial attempts can be preserved and inspected but never become completion.
"""
from dataclasses import dataclass
import json
from .attempts import verify_chain
from .evidence import SealedEvidence,StorageFailure,canonical,sha,HEX


@dataclass(frozen=True)
class AttemptSnapshot:
    evidence: SealedEvidence
    head_sha256: str
    record_count: int


def _verify_entries(entries, *, chain_key, chain_key_id, expected_head_sha256,
                    expected_record_count, expected_identity):
    if (type(entries) is not list or not entries or type(expected_head_sha256) is not str
        or not HEX.fullmatch(expected_head_sha256) or type(expected_record_count) is not int
        or expected_record_count < 1 or type(expected_identity) is not dict
        or set(expected_identity)!={'campaign_id','attempt_id','subject_id','source_sha256'}):
        raise StorageFailure('owner-retained nonempty attempt snapshot anchor required')
    verify_chain(entries,chain_key,chain_key_id,expected_head_sha256=expected_head_sha256,
                 expected_record_count=expected_record_count)
    if any(entries[-1]['record'].get(k)!=v for k,v in expected_identity.items()):
        raise StorageFailure('attempt snapshot source/campaign/attempt/subject mismatch')
    return entries[-1]['record']['state']


def seal_attempt_snapshot(store, entries, *, member_key, member_key_id,
    storage_scope_sha256, chain_key, chain_key_id, expected_head_sha256,
    expected_record_count, expected_identity):
    terminal=_verify_entries(entries,chain_key=chain_key,chain_key_id=chain_key_id,
        expected_head_sha256=expected_head_sha256,expected_record_count=expected_record_count,
        expected_identity=expected_identity)
    data=canonical(entries)
    evidence=store.put(data,state='SEALED_COMPLETE' if terminal=='SEALED_COMPLETE' else 'SEALED_PARTIAL')
    evidence.verify(member_key,member_key_id)
    if evidence.storage_scope_sha256!=storage_scope_sha256:
        raise StorageFailure('sealed attempt snapshot storage scope mismatch')
    if evidence.reference.sha256!=sha(data) or evidence.reference.size_bytes!=len(data):
        raise StorageFailure('sealed attempt snapshot original byte mismatch')
    return AttemptSnapshot(evidence,expected_head_sha256,expected_record_count)


def read_attempt_snapshot(snapshot, read_exact, *, member_key, member_key_id,
    storage_scope_sha256, chain_key, chain_key_id, expected_head_sha256,
    expected_record_count, expected_identity, require_complete=False):
    """read_exact is the trusted owner's exact-version capability, not an RPC path.

    For S3 partial preservation the owner passes reader.read with
    require_complete=False; all science/audit completion still requires terminal.
    """
    if (type(snapshot) is not AttemptSnapshot or snapshot.head_sha256!=expected_head_sha256
        or snapshot.record_count!=expected_record_count):
        raise StorageFailure('attempt snapshot cannot supply its own trusted anchor')
    evidence=snapshot.evidence
    evidence.verify(member_key,member_key_id)
    if evidence.storage_scope_sha256!=storage_scope_sha256:
        raise StorageFailure('attempt snapshot storage scope mismatch')
    data=read_exact(evidence)
    if (type(data) is not bytes or sha(data)!=evidence.reference.sha256
        or len(data)!=evidence.reference.size_bytes):
        raise StorageFailure('attempt snapshot exact-byte readback mismatch')
    try:entries=json.loads(data)
    except Exception as exc:raise StorageFailure('malformed attempt snapshot bytes') from exc
    if canonical(entries)!=data:raise StorageFailure('attempt snapshot bytes are not canonical original')
    terminal=_verify_entries(entries,chain_key=chain_key,chain_key_id=chain_key_id,
        expected_head_sha256=expected_head_sha256,expected_record_count=expected_record_count,
        expected_identity=expected_identity)
    wanted='SEALED_COMPLETE' if terminal=='SEALED_COMPLETE' else 'SEALED_PARTIAL'
    if evidence.state!=wanted or (require_complete and terminal!='SEALED_COMPLETE'):
        raise StorageFailure('partial attempt snapshot cannot qualify completion')
    return entries
