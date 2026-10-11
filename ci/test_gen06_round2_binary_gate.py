"""Synthetic public fixtures only: fail closed and keep private child output private."""
import copy,json,os,pathlib,subprocess,sys,tempfile,unittest
WRAPPER=pathlib.Path(__file__).with_name('gen06_round2_binary_gate.py')

def completed():
 return {'status':'PASS_INDEPENDENT_BINARY_AND_SEMANTIC_EVIDENCE_CHECKS','checks':{'frozen_sources':{'files':166,'all_sha256_match':True},'archives':{k:{'member_count':n,'boundaries':{str(i):{} for i in range(12)},'complete_captures':8 if k=='T2_partial' else 12} for k,n in [('T1',60),('T2',60),('T2_partial',68)]},'sqlite_objects':{'references':30,'unique_objects':23,'sha256_and_sizes_all_match':True},'sqlite_integrity':{k:23 for k in ['integrity','foreign_keys','global_verifier','canonical_digests']},'ll3_d10':{t:{'status':'PASS_INDEPENDENT_SOURCE_RECONSTRUCTION'} for t in ['T1','T2']},'d6_d7':{t:{'D6':'PASS','D7':'PASS'} for t in ['T1','T2']},'restart_revision':{t:{'restart_clean':'PASS','restart_pending':'PASS','typed_revision':'PASS'} for t in ['T1','T2']}}}

class PublicBoundary(unittest.TestCase):
 def run_fixture(self,payload,exit_code=0):
  with tempfile.TemporaryDirectory() as area:
   root=pathlib.Path(area);tool=root/'.github/audit/gen06_round2_binary_verify.py';tool.parent.mkdir(parents=True)
   tool.write_text('import json,pathlib,sys\nprint("SYNTHETIC_PRIVATE_OUTPUT_DO_NOT_PUBLISH")\npathlib.Path(__file__).with_name("round2_binary_audit_result.json").write_text('+repr(json.dumps(payload))+')\nsys.exit('+str(exit_code)+')\n')
   result=subprocess.run([sys.executable,str(WRAPPER),str(root)],capture_output=True,text=True,env={**os.environ,'RUNNER_TEMP':str(root)})
   self.assertNotIn('SYNTHETIC_PRIVATE_OUTPUT_DO_NOT_PUBLISH',result.stdout+result.stderr)
   summary=json.loads((root/'adamon-r2-public-sanitized.json').read_text());return result,summary
 def test_complete_requires_all_checks(self):
  result,summary=self.run_fixture(completed());self.assertEqual(result.returncode,0);self.assertEqual(summary['status'],'BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING')
 def test_incomplete_verifier_cannot_pass(self):
  payload=completed();payload['checks']['sqlite_integrity']['global_verifier']=22;result,summary=self.run_fixture(payload);self.assertNotEqual(result.returncode,0);self.assertEqual(summary['status'],'INCOMPLETE')
 def test_filtered_codes_and_ordinal_only(self):
  payload={'status':'FAILED_OR_INCOMPLETE','failure':{'type':'AssertionError','message':'Global Verifier failed SYNTHETIC_PRIVATE_OUTPUT_DO_NOT_PUBLISH'},'failure_verifier':{'ordinal':1,'codes':['PERSON_MODEL','PERSON_OBSERVATION','SYNTHETIC_PRIVATE_OUTPUT_DO_NOT_PUBLISH'],'result':{'sensitive':'SYNTHETIC_PRIVATE_OUTPUT_DO_NOT_PUBLISH'}},'checks':{}}
  result,summary=self.run_fixture(payload,1);self.assertNotEqual(result.returncode,0);self.assertEqual(summary['diagnostic']['sqlite_object_ordinal'],1);self.assertEqual(summary['diagnostic']['verifier_failure_codes'],['PERSON_MODEL','PERSON_OBSERVATION']);self.assertNotIn('sensitive',result.stdout)

if __name__=='__main__':unittest.main()
