"""Patch-boundary tests; never invoke Runner, research, network, or a workflow."""
import hashlib, importlib.util, json, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class PatchContracts(unittest.TestCase):
    def test_exact_public_pin(self):
        data=json.loads((ROOT/'upstream-lock.json').read_text())
        self.assertEqual(data['commit'],'197ca027b90de199464dee3bb9ff198a1db60967')
        self.assertEqual(len(data['original_sources']),4)
    def test_no_worker_spawn_fallback(self):
        patch=(ROOT/'runner-v4.patch').read_text()
        added='\n'.join(line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++'))
        self.assertNotIn('processInvoker.ExecuteAsync',added)
        self.assertIn('P4ProtectedBridge.SpawnWorkerAsync',added)
        self.assertIn('P4ProtectedBridge.RevokeListener()',added)
    def test_no_setup_or_shell_fallback(self):
        patch=(ROOT/'runner-v4.patch').read_text()
        self.assertIn('-                    jobSteps = await jobExtension.InitializeJob',patch)
        self.assertIn('-                    await jobExtension.FinalizeJob',patch)
        self.assertIn('-                await step.RunAsync();',patch)
    def test_fixed_private_transport(self):
        code=(ROOT/'overlays/P4ProtectedBridge.cs').read_text()
        self.assertIn('ListenerFd = 198, WorkerFd = 199',code)
        self.assertIn('sendmsg',code)
        self.assertIn('P4_PRIVATE_STREAM_REQUIRED',code)
        self.assertNotIn('Process.Start',code)
        self.assertNotIn('GetEnvironmentVariable(',code)
    def test_assignment_reinterpretation_denied(self):
        code=(ROOT/'overlays/P4ProtectedBridge.cs').read_text()
        self.assertIn('DuplicatePropertyNameHandling.Error',code)
        self.assertIn('P4_ASSIGNMENT_MUTATION',code)
        self.assertIn('step.Condition!="success()"',code)
        self.assertIn('inputs.Count!=1',code)
    def test_bootstrap_finite_wait(self):
        code=(ROOT/'overlays/P4ProtectedBridge.cs').read_text()
        self.assertIn('timeout.CancelAfter(TimeSpan.FromSeconds(30))',code)
    def test_applier_wrong_head_fails(self):
        spec=importlib.util.spec_from_file_location('applier',ROOT/'apply_patch.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['git','init','-q',directory],check=True)
            subprocess.run(['git','-C',directory,'-c','user.name=Test','-c','user.email=test@example.invalid','commit','--allow-empty','-qm','test'],check=True)
            with self.assertRaisesRegex(ValueError,'UPSTREAM_HEAD_MISMATCH'):module.apply(directory)
if __name__=='__main__':unittest.main()
