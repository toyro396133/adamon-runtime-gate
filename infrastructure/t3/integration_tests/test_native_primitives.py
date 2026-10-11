"""Actual Linux native primitive tests; no privileged spawn or research."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from infrastructure.t3.security.native import Native


class NativePrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('gcc missing: native implementation UNVERIFIED')
        cls.temporary = tempfile.TemporaryDirectory(prefix='t3-native-synthetic-')
        cls.library = Path(cls.temporary.name) / 'libp4.so'
        source = Path(__file__).resolve().parents[1] / 'security/native_supervisor.c'
        subprocess.run(['gcc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(cls.library)], check=True, capture_output=True)
        cls.digest = hashlib.sha256(cls.library.read_bytes()).hexdigest()
        cls.native = Native(str(cls.library), cls.digest)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_memfd_is_sealed_against_mutation(self):
        fd = self.native.sealed_key(b'x' * 32)
        try:
            self.assertEqual(os.read(fd, 32), b'x' * 32)
            with self.assertRaises(PermissionError): os.write(fd, b'y')
        finally:
            os.close(fd)

    def test_native_root_spawn_denied_before_any_creation(self):
        with self.assertRaises(OSError):
            self.native.spawn_candidate(-1, -1, 0, 0, -1)

    def test_wrong_native_digest_rejected(self):
        with self.assertRaises(ValueError):
            Native(str(self.library), '0' * 64)


if __name__ == '__main__':
    unittest.main()
