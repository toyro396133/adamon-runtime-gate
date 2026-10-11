"""Closed MICRO metadata binding. Expected pins are privileged private configuration.

No fixture, subject identifiers, schedules, or source contents are public here.
The generic receipt schema remains unchanged; jobs/version metadata lives in a
signed immutable inventory member and is carried into the AUDIT manifest.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from .receipts import ReceiptError, canonical

_FIELDS = frozenset({'authority_version','control_id','jobs_sha256','registry_sha256',
                    'fixture_sha256','schedule_sha256','life_cycles',
                    'structural_direct_processings','direct_batch_calls'})

@dataclass(frozen=True)
class MicroAuthorityPins:
    metadata: dict

    def __post_init__(self):
        expected = self.metadata
        if type(expected) is not dict or set(expected) != _FIELDS:
            raise ReceiptError('closed privileged MICRO authority metadata required')
        if expected['authority_version'] != 'MICRO_V4_1' or type(expected['control_id']) is not str or not expected['control_id']:
            raise ReceiptError('active MICRO authority version required')
        for name, value in expected.items():
            if name.endswith('_sha256') and (type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None):
                raise ReceiptError('exact MICRO authority hash required')
        for name in ('life_cycles','structural_direct_processings','direct_batch_calls'):
            if type(expected[name]) is not int or expected[name] < 0:
                raise ReceiptError('exact MICRO count required')
        object.__setattr__(self, 'metadata', MappingProxyType(dict(expected)))

    def verify_metadata(self, actual):
        if type(actual) is not dict or canonical(actual) != canonical(dict(self.metadata)):
            raise ReceiptError('MICRO authority/jobs/fixture/schedule mismatch')
        return dict(self.metadata)

    def verify_receipt(self, payload):
        for key in ('control_id','registry_sha256','fixture_sha256','schedule_sha256',
                    'life_cycles','structural_direct_processings','direct_batch_calls'):
            if type(payload.get(key)) is not type(self.metadata[key]) or payload.get(key) != self.metadata[key]:
                raise ReceiptError('MICRO receipt not bound to active authority')

    def inspect_reader(self, reader):
        reference = reader.reference('micro_authority')
        raw = reader.read_version(reference['object_id'], reference['version_id'])
        if (len(raw) != reference['size_bytes'] or hashlib.sha256(raw).hexdigest() != reference['sha256']):
            raise ReceiptError('immutable MICRO authority member mismatch')
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ReceiptError('duplicate MICRO metadata key')
                out[key] = value
            return out
        try: actual = json.loads(raw, object_pairs_hook=pairs)
        except (ValueError, UnicodeError) as exc: raise ReceiptError('invalid MICRO authority member') from exc
        return self.verify_metadata(actual)
