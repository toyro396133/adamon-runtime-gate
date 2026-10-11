from pathlib import Path
import unittest
from infrastructure.t3.preflight.check import inspect_host

class PreflightTests(unittest.TestCase):
    def test_never_authorizes_execution(self):
        result=inspect_host()
        self.assertFalse(result['execution_authorized']);self.assertFalse(result['research_executed'])
        self.assertEqual(result['status'],'PREFLIGHT_INCOMPLETE')
    def test_runtime_security_not_inferred_from_api(self):
        result=inspect_host()
        self.assertEqual(result['checks']['pidfd_api']['runtime_isolation'],'UNVERIFIED')
        self.assertEqual(result['checks']['private_s3_kms_object_lock']['state'],'UNVERIFIED')
    def test_workflow_not_installed(self):
        template=Path(__file__).resolve().parents[1]/'nonresearch.yml.template'
        data=template.read_text()
        self.assertIn('REQUIRES_OWNER_PIN',data)
        self.assertNotIn('workflow_call:',data)
        self.assertNotIn('life.execute',data)
    def test_no_environment_secret_values(self):
        import json
        import os
        os.environ['T3_TEST_CANARY_SECRET']='do-not-emit-this-marker'
        try:self.assertNotIn('do-not-emit-this-marker',json.dumps(inspect_host()))
        finally:del os.environ['T3_TEST_CANARY_SECRET']

if __name__=='__main__':unittest.main()
