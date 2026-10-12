"""Owner/channel-bound storage authorization, additive to accepted evidence APIs.

This implementation authenticates application requests. It does not configure OS
UIDs, IAM, KMS or ObjectLock; those require separately authorized live preflight.
Only the fixed NONRESEARCH chain is enabled here. No research permit or PASS API.
"""
from __future__ import annotations
import json
import re
import sqlite3
import time
from types import MappingProxyType
from .evidence import StorageFailure, canonical, sha, HEX
from ..security.protocol import sign, verify, spki_digest

CAPABILITY_DOMAIN = 'ADAMON-NONRESEARCH-STORAGE-CAPABILITY-V1'
REQUEST_DOMAIN = 'ADAMON-NONRESEARCH-STORAGE-REQUEST-V1'
JOURNAL_DOMAIN = 'ADAMON-NONRESEARCH-STORAGE-JOURNAL-V1'
IDENTIFIER = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
OPERATIONS = MappingProxyType({'PRODUCER': frozenset({'start', 'preserve'}),
                              'AUDITOR': frozenset({'read_member'}),
                              'REVIEWER': frozenset({'read_member'})})
CAPABILITY_FIELDS = frozenset({'version','scope','capability_id','role','subject_id',
    'campaign_id','attempt_id','job_binding_sha256','permit_id','source_sha256',
    'fixture_sha256','storage_scope_sha256','channel_spki_sha256','issued_at','expires_at'})
REQUEST_FIELDS = frozenset({'version','capability_sha256','operation','argument_sha256','nonce'})


class StorageAccessGate:
    """Fixed owner trust + exact retained binding; atomic one-use signed requests.

    Request nonce consumption commits *before* byte operations. A failure cannot
    reuse authorization: a new signed request is required, and attempt-chain
    semantics decide whether retry is admissible. Expiration is checked at each
    operation. Explicit revoke applies to all future requests for a capability.
    SQLite is a local persistence mechanism, not privileged-admin immutability.
    """
    def __init__(self, database, *, owner_keys, expected_binding, journal_signer,
                 journal_key_id, clock=time.time, max_artifact_bytes=64*1024*1024):
        self.database = database
        self.keys = MappingProxyType(dict(owner_keys))
        self.binding = MappingProxyType(dict(expected_binding))
        required = CAPABILITY_FIELDS - {'version','scope','capability_id','role',
                                       'channel_spki_sha256','issued_at','expires_at'}
        if set(self.binding) != required:
            raise StorageFailure('exact owner-retained storage binding required')
        if type(max_artifact_bytes) is not int or not 0 < max_artifact_bytes <= 1024*1024*1024:
            raise StorageFailure('bounded original byte transfer required')
        self.clock, self.limit = clock, max_artifact_bytes
        self.signer, self.key_id = journal_signer, journal_key_id
        with sqlite3.connect(database) as con:
            con.execute('PRAGMA synchronous=FULL')
            con.executescript('''CREATE TABLE IF NOT EXISTS storage_requests
                (sequence INTEGER PRIMARY KEY, capability_id TEXT NOT NULL, nonce TEXT NOT NULL,
                 envelope BLOB NOT NULL, digest TEXT UNIQUE NOT NULL,
                 UNIQUE(capability_id,nonce));
                CREATE TABLE IF NOT EXISTS storage_revocations
                (capability_id TEXT PRIMARY KEY, envelope BLOB NOT NULL);
                CREATE TRIGGER IF NOT EXISTS requests_no_update BEFORE UPDATE ON storage_requests
                BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS requests_no_delete BEFORE DELETE ON storage_requests
                BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS revoke_no_update BEFORE UPDATE ON storage_revocations
                BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS revoke_no_delete BEFORE DELETE ON storage_revocations
                BEGIN SELECT RAISE(ABORT,'immutable'); END;''')

    def _capability(self, capability, channel_key):
        try:
            payload = verify(capability, self.keys, CAPABILITY_DOMAIN)
        except Exception as exc:
            raise StorageFailure('invalid owner storage capability') from exc
        if (type(payload) is not dict or set(payload) != CAPABILITY_FIELDS
            or type(payload['version']) is not int or payload['version'] != 1
            or payload['scope'] != 'NONRESEARCH_LOCAL_PROCESS_CANARY'
            or type(payload['role']) is not str or payload['role'] not in OPERATIONS
            or any(payload.get(k) != v for k,v in self.binding.items())):
            raise StorageFailure('capability role/Job/permit/subject/source/fixture/storage mismatch')
        for field in ('capability_id','subject_id','campaign_id','attempt_id','permit_id'):
            if type(payload[field]) is not str or not IDENTIFIER.fullmatch(payload[field]):
                raise StorageFailure('invalid opaque storage identity')
        for field in ('job_binding_sha256','source_sha256','fixture_sha256','storage_scope_sha256','channel_spki_sha256'):
            if type(payload[field]) is not str or not HEX.fullmatch(payload[field]):
                raise StorageFailure('invalid storage digest')
        now = self.clock()
        if (type(payload['issued_at']) is not int or type(payload['expires_at']) is not int
            or not payload['issued_at'] <= now < payload['expires_at']
            or not 0 < payload['expires_at']-payload['issued_at'] <= 3600):
            raise StorageFailure('expired or overlong storage lease')
        try:
            channel_digest = spki_digest(channel_key)
        except Exception as exc:
            raise StorageFailure('storage requester channel key invalid') from exc
        if payload['channel_spki_sha256'] != channel_digest:
            raise StorageFailure('storage requester channel identity mismatch')
        return payload

    def authorize(self, capability, request, channel_key, *, operation, argument):
        payload = self._capability(capability, channel_key)
        if operation not in OPERATIONS[payload['role']]:
            raise StorageFailure('cross-role storage operation denied')
        try:
            query = verify(request, {'channel':channel_key}, REQUEST_DOMAIN)
        except Exception as exc:
            raise StorageFailure('invalid authenticated storage request') from exc
        if (type(query) is not dict or set(query) != REQUEST_FIELDS
            or type(query['version']) is not int or query['version'] != 1
            or query['capability_sha256'] != sha(canonical(capability))
            or query['operation'] != operation or query['argument_sha256'] != sha(canonical(argument))
            or type(query['nonce']) is not str or not HEX.fullmatch(query['nonce'])):
            raise StorageFailure('storage request capability/operation/argument/nonce mismatch')
        try:
            with sqlite3.connect(self.database, timeout=15) as con:
                con.execute('PRAGMA synchronous=FULL')
                con.execute('BEGIN IMMEDIATE')
                # A contended lock must not extend the credential lifetime.
                self._capability(capability,channel_key)
                if con.execute('SELECT 1 FROM storage_revocations WHERE capability_id=?',
                               (payload['capability_id'],)).fetchone():
                    raise StorageFailure('storage capability revoked')
                rows = [json.loads(r[0]) for r in con.execute('SELECT envelope FROM storage_requests ORDER BY sequence')]
                self.verify_journal(rows)
                body = dict(version=1,sequence=len(rows)+1,
                    previous_sha256=sha(canonical(rows[-1])) if rows else None,
                    capability_sha256=sha(canonical(capability)), capability_id=payload['capability_id'],
                    role=payload['role'], nonce=query['nonce'], operation=operation,
                    argument_sha256=query['argument_sha256'], authorized_at=int(self.clock()))
                entry = sign(body, self.signer, self.key_id, JOURNAL_DOMAIN)
                con.execute('INSERT INTO storage_requests VALUES(?,?,?,?,?)',
                    (body['sequence'],payload['capability_id'],query['nonce'],canonical(entry),sha(canonical(entry))))
                return entry
        except sqlite3.IntegrityError as exc:
            raise StorageFailure('replayed storage request; atomic consume denied') from exc

    def revoke(self, capability_id):
        """Owner-process administration; not exposed to any role RPC."""
        if type(capability_id) is not str or not IDENTIFIER.fullmatch(capability_id):
            raise StorageFailure('invalid capability revocation')
        entry = sign(dict(version=1,capability_id=capability_id,revoked_at=int(self.clock())),
                     self.signer,self.key_id,JOURNAL_DOMAIN)
        with sqlite3.connect(self.database) as con:
            con.execute('PRAGMA synchronous=FULL')
            con.execute('INSERT OR IGNORE INTO storage_revocations VALUES(?,?)',(capability_id,canonical(entry)))

    def journal(self):
        with sqlite3.connect(f'file:{self.database}?mode=ro',uri=True) as con:
            con.execute('PRAGMA query_only=ON')
            rows = [json.loads(r[0]) for r in con.execute('SELECT envelope FROM storage_requests ORDER BY sequence')]
        self.verify_journal(rows)
        return rows

    def verify_journal(self, entries, *, expected_head_sha256=None, expected_count=None):
        previous = None
        seen = set()
        for index,entry in enumerate(entries,1):
            try:
                body = verify(entry, {self.key_id:self.signer.public_key()}, JOURNAL_DOMAIN)
            except Exception as exc:
                raise StorageFailure('invalid storage authorization journal signature') from exc
            fields = {'version','sequence','previous_sha256','capability_sha256','capability_id',
                      'role','nonce','operation','argument_sha256','authorized_at'}
            if (set(body) != fields or type(body['version']) is not int or body['version'] != 1
                or type(body['sequence']) is not int or body['sequence'] != index
                or body['previous_sha256'] != previous or type(body['role']) is not str or body['role'] not in OPERATIONS
                or body['operation'] not in OPERATIONS[body['role']]
                or (body['capability_id'],body['nonce']) in seen):
                raise StorageFailure('storage authorization journal reorder/replay/role mismatch')
            seen.add((body['capability_id'],body['nonce']))
            previous = sha(canonical(entry))
        if ((expected_head_sha256 is not None and previous != expected_head_sha256)
            or (expected_count is not None and (type(expected_count) is not int or len(entries) != expected_count))):
            raise StorageFailure('externally retained storage journal anchor mismatch')
        return dict(head_sha256=previous,record_count=len(entries),scope='LOCAL_SIGNED_AUTHORIZATION_NOT_IAM_PROOF')


class ScopedNonresearchBroker:
    """Authenticated fixed broker API; original artifacts stay byte-only."""
    def __init__(self, broker, gate):
        if (broker.binding.get('source_sha256') != gate.binding['source_sha256']
            or broker.binding.get('fixture_sha256') != gate.binding['fixture_sha256']
            or broker.permit_id != gate.binding['permit_id']
            or broker.producer.scope != gate.binding['storage_scope_sha256']
            or any(broker.identity.get(k)!=gate.binding[k] for k in ('campaign_id','attempt_id','subject_id'))
            or sha(canonical(broker.binding)) != gate.binding['job_binding_sha256']):
            raise StorageFailure('broker authorization binding mismatch')
        self.broker,self.gate = broker,gate

    def start(self, capability, request, channel_key):
        self.gate.authorize(capability,request,channel_key,operation='start',argument={})
        return self.broker.start()

    def preserve(self, capability, request, channel_key, receipt, original_artifact):
        if type(original_artifact) is not bytes or not 0 < len(original_artifact) <= self.gate.limit:
            raise StorageFailure('bounded immutable original byte transfer required')
        argument = dict(receipt_sha256=sha(canonical(receipt)),artifact_sha256=sha(original_artifact),
                        artifact_size_bytes=len(original_artifact))
        self.gate.authorize(capability,request,channel_key,operation='preserve',argument=argument)
        return self.broker.preserve(receipt, original_artifact)


class ScopedInventoryReadback:
    """Auditor/reviewer only, exact signed VersionId registry, no write methods."""
    def __init__(self, reader, gate):
        if any(m.storage_scope_sha256 != gate.binding['storage_scope_sha256'] for m in reader._members.values()):
            raise StorageFailure('reader authorization scope mismatch')
        self.reader,self.gate = reader,gate

    def read_member(self, capability, request, channel_key, label):
        reference = self.reader.reference(label)
        argument = dict(label=label,reference=reference)
        self.gate.authorize(capability,request,channel_key,operation='read_member',argument=argument)
        return self.reader.read_version(reference['object_id'],reference['version_id'])
