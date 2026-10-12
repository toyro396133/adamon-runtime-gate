"""Real upstream graph inspection is optional by explicit existing checkout path."""
import json
import os
import pathlib
import unittest
from infrastructure.t3.runner.build_graph import inspect

class BuildGraphTests(unittest.TestCase):
    def test_receipt_never_claims_build_or_transitive_restore(self):
        receipt=json.loads((pathlib.Path(__file__).parents[1]/'build_prerequisites_receipt.json').read_text())
        self.assertFalse(receipt['full_runner_build_verified'])
        self.assertFalse(receipt['transitive_package_content_pins_verified'])
        self.assertEqual(receipt['network_requests'],0)
        self.assertIn('--no-restore',receipt['offline_build_argv'])
        self.assertEqual(set(receipt['projects']),{
            'src/Runner.Listener/Runner.Listener.csproj','src/Runner.Worker/Runner.Worker.csproj',
            'src/Runner.Common/Runner.Common.csproj','src/Runner.Sdk/Runner.Sdk.csproj','src/Sdk/Sdk.csproj'})
