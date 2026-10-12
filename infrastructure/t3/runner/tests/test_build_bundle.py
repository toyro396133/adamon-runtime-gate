import base64
import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from infrastructure.t3.runner.build_bundle import dependency_closure, verify_build_receipt

class BuildBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        (self.root/'src/Test').mkdir(parents=True);(self.root/'feed').mkdir()
        (self.root/'src/Test/Test.csproj').write_text('<Project/>')
        (self.root/'src/ActionsRunner.sln').write_text('"Test\\Test.csproj"')
        raw=b'owner-original-package';self.package=self.root/'feed/example.1.2.3.nupkg';self.package.write_bytes(raw)
        self.lock={'version':1,'dependencies':{'net8.0':{'Example':{'type':'Transitive','resolved':'1.2.3','contentHash':base64.b64encode(hashlib.sha512(raw).digest()).decode()}}}}
        self.save()
    def tearDown(self): self.temp.cleanup()
    def save(self): (self.root/'src/Test/packages.lock.json').write_text(json.dumps(self.lock))
    def valid(self): return dependency_closure(self.root,self.root/'feed')
    def test_exact_closure(self): self.assertEqual(self.valid()['packages']['example/1.2.3']['sha256'],hashlib.sha256(self.package.read_bytes()).hexdigest())
    def test_missing_hash_rejected(self):
        self.valid();del self.lock['dependencies']['net8.0']['Example']['contentHash'];self.save()
        with self.assertRaisesRegex(ValueError,'BUILD_CONTENT_HASH_MISSING'): self.valid()
    def test_floating_rejected(self):
        self.valid();self.lock['dependencies']['net8.0']['Example']['resolved']='1.*';self.save()
        with self.assertRaisesRegex(ValueError,'BUILD_FLOATING_TRANSITIVE_PACKAGE'): self.valid()
    def test_package_mutation_rejected(self):
        self.valid();self.package.write_bytes(b'mutated')
        with self.assertRaisesRegex(ValueError,'BUILD_PACKAGE_BYTES_MISMATCH'): self.valid()
    def test_lock_missing_rejected(self):
        self.valid();(self.root/'src/Test/packages.lock.json').unlink()
        with self.assertRaisesRegex(ValueError,'BUILD_LOCK_MISSING'): self.valid()
    def test_symlink_package_rejected(self):
        self.valid();self.package.unlink();self.package.symlink_to(self.root/'src/ActionsRunner.sln')
        with self.assertRaisesRegex(ValueError,'BUILD_PACKAGE_MISSING'): self.valid()
    def test_unfrozen_bundle_cannot_validate_build(self):
        with self.assertRaisesRegex(ValueError,'BUILD_DEPENDENCIES_NOT_FROZEN'):
            verify_build_receipt({'status':'BLOCKED_UNFROZEN_TRANSITIVE_CONTENT'}, {}, self.root)
    def receipt_fixture(self):
        bundle={'status':'CONTENT_PINNED_READY_FOR_OWNER_BUILD','dependency_closure':self.valid(),
            'commands':[dict(phase=p,argv=['dotnet',p]) for p in ('restore','build','tests')]}
        def ref(name,raw):
            (self.root/name).write_bytes(raw)
            return dict(relative=name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
        receipt=dict(version=1,bundle_sha256=hashlib.sha256(json.dumps(bundle,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            phases={p:dict(argv=['dotnet',p],exit_code=0,log=ref(p+'.log',b'original test log')) for p in ('restore','build','tests')},
            outputs={p:ref(p,b'MZsynthetic-pe') for p in ('Runner.Listener.dll','Runner.Worker.dll')},
            trx=ref('tests.trx',b'<TestRun><ResultSummary><Counters total="1" executed="1" passed="1"/></ResultSummary></TestRun>'))
        return bundle,receipt
    def test_synthetic_receipt_validation_is_not_full_build(self):
        bundle,receipt=self.receipt_fixture();result=verify_build_receipt(bundle,receipt,self.root)
        self.assertEqual(result['status'],'OWNER_BUILD_OUTPUTS_VALIDATED_PENDING_INDEPENDENT_REVIEW');self.assertFalse(result['execution_authorized'])
    def test_each_failed_phase_rejected_with_valid_baseline(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root)
        for p in receipt['phases']:
            bad=copy.deepcopy(receipt);bad['phases'][p]['exit_code']=1
            with self.assertRaisesRegex(ValueError,'BUILD_PHASE_FAILED'): verify_build_receipt(bundle,bad,self.root)
    def test_missing_worker_output(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root);del receipt['outputs']['Runner.Worker.dll']
        with self.assertRaisesRegex(ValueError,'BUILD_OUTPUT_MISSING'): verify_build_receipt(bundle,receipt,self.root)
    def test_trx_skips_not_success(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root)
        raw=b'<TestRun><ResultSummary><Counters total="2" executed="1" passed="1"/></ResultSummary></TestRun>'
        (self.root/'tests.trx').write_bytes(raw);receipt['trx'].update(sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
        with self.assertRaisesRegex(ValueError,'BUILD_TESTS_INCOMPLETE'): verify_build_receipt(bundle,receipt,self.root)

    def test_original_build_artifact_mutation_rejected(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root)
        (self.root/'build.log').write_bytes(b'mutated log')
        with self.assertRaisesRegex(ValueError,'BUILD_ARTIFACT_BYTES_MISMATCH'): verify_build_receipt(bundle,receipt,self.root)
    def test_conflicting_failure_counters_rejected_individually(self):
        for name in ('failed','error','timeout','aborted','inconclusive','notExecuted','disconnected','warning','pending'):
            with self.subTest(counter=name):
                bundle,receipt=self.receipt_fixture()
                verify_build_receipt(bundle,receipt,self.root)
                raw=('<TestRun><ResultSummary><Counters total="1" executed="1" passed="1" '+name+'="1"/></ResultSummary></TestRun>').encode()
                (self.root/'tests.trx').write_bytes(raw)
                receipt['trx'].update(sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
                with self.assertRaisesRegex(ValueError,'BUILD_TESTS_INCOMPLETE'):
                    verify_build_receipt(bundle,receipt,self.root)
    def test_other_bundle_digest_rejected(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root)
        receipt['bundle_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'BUILD_RECEIPT_BUNDLE_MISMATCH'): verify_build_receipt(bundle,receipt,self.root)
    def test_path_escape_rejected(self):
        bundle,receipt=self.receipt_fixture();verify_build_receipt(bundle,receipt,self.root)
        receipt['trx']['relative']='../foreign.trx'
        with self.assertRaisesRegex(ValueError,'BUILD_ARTIFACT_ESCAPE'): verify_build_receipt(bundle,receipt,self.root)

class ExportFeedTests(unittest.TestCase):
    setUp = BuildBundleTests.setUp
    tearDown = BuildBundleTests.tearDown
    save = BuildBundleTests.save
    valid = BuildBundleTests.valid
    def test_export_exact_originals_and_no_overwrite(self):
        from infrastructure.t3.runner.build_bundle import export_feed
        cache=self.root/'cache/example/1.2.3';cache.mkdir(parents=True)
        (cache/self.package.name).write_bytes(self.package.read_bytes())
        output=self.root/'owner-feed'
        closure=export_feed(self.root,self.root/'cache',output)
        self.assertEqual(closure,self.valid())
        with self.assertRaisesRegex(ValueError,'BUILD_FEED_OUTPUT_EXISTS'): export_feed(self.root,self.root/'cache',output)
    def test_modified_cache_never_published(self):
        from infrastructure.t3.runner.build_bundle import export_feed
        cache=self.root/'cache/example/1.2.3';cache.mkdir(parents=True)
        (cache/self.package.name).write_bytes(b'mutated')
        output=self.root/'owner-feed'
        with self.assertRaisesRegex(ValueError,'BUILD_PACKAGE_BYTES_MISMATCH'): export_feed(self.root,self.root/'cache',output)
        self.assertFalse(output.exists())
