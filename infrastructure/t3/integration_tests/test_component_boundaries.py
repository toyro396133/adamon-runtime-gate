"""Synthetic component compatibility checks; no scientific objects or authority."""
import hashlib
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.roles import receipts
from infrastructure.t3.security import protocol


class ComponentBoundaryTests(unittest.TestCase):
    def test_canonical_bytes_identical_between_security_and_role_receipts(self):
        payload = {'version': 4, 'role': 'AUDIT', 'binding': {'sample': 'synthetic'},
                   'checks': [True, False, None, 42]}
        self.assertEqual(receipts.canonical(payload), protocol.canonical(payload))

    def test_actual_role_signature_is_verified_with_same_security_domain_bytes(self):
        key = Ed25519PrivateKey.generate()
        payload = {'version': 4, 'role': 'AUDIT', 'test': 'NO_RESEARCH'}
        envelope = receipts.seal(payload, 'AUDIT', 'SYNTHETIC-AUDIT-RECEIPT', key)
        received = protocol.verify({**envelope, 'key_id': 'synthetic'},
                                   {'synthetic': key.public_key()}, 'SYNTHETIC-AUDIT-RECEIPT')
        self.assertEqual(received, payload)
        with self.assertRaises(protocol.Denied):
            protocol.verify({**envelope, 'key_id': 'synthetic'},
                            {'synthetic': key.public_key()}, 'SYNTHETIC-LIFE-RECEIPT')

    def test_noncanonical_values_rejected_by_both_components(self):
        for value in ({'v': .1}, {'v': 2**53}, {'v': '\u05d0'}, {1: 'nonstring'}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(receipts.ReceiptError): receipts.canonical(value)
                with self.assertRaises(protocol.Denied): protocol.canonical(value)

    def test_received_duplicates_rejected_before_signature_validation(self):
        raw = b'{"role":"LIFE","role":"AUDIT"}'
        with self.assertRaises(protocol.Denied): protocol.decode(raw)

    def test_hashes_use_exact_same_canonical_bytes(self):
        payload = {'a': [1, None, True], 'z': 'synthetic'}
        self.assertEqual(protocol.digest(payload), hashlib.sha256(receipts.canonical(payload)).hexdigest())


if __name__ == '__main__':
    unittest.main()
