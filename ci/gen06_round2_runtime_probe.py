"""Publish only bounded environment diagnostics, never private rows or raw errors."""
import json,os,pathlib,subprocess,sys,tempfile
source=pathlib.Path(sys.argv[1]).resolve();output=source/'.github/audit/round2_runtime_probe.json'
if output.exists():raise SystemExit('ENVIRONMENT: stale diagnostic output')
with tempfile.TemporaryDirectory(prefix='adamon-r2-private-run-',dir=os.environ.get('RUNNER_TEMP')) as area:
 with (pathlib.Path(area)/'private-probe.log').open('wb') as log:
  child=subprocess.run([sys.executable,str(source/'.github/audit/gen06_round2_binary_verify.py'),'--runtime-probe'],cwd=source,stdout=log,stderr=subprocess.STDOUT)
 if child.returncode or not output.is_file():raise SystemExit('BASELINE_DIAGNOSTIC_FAILED: raw diagnostics suppressed')
 result=json.loads(output.read_text());probe=result['runtime_probe'];environment=result['environment']
 allowed={'PERSON_OBSERVATION','PERSON_MODEL'}
 codes=probe['verifier_codes']
 if any(code not in allowed for code in codes):raise SystemExit('BASELINE_DIAGNOSTIC_UNAPPROVED_CODE')
 import re
 if not all(re.fullmatch(r'\d+\.\d+\.\d+',environment[key]) for key in ['python','sqlite']):raise SystemExit('ENVIRONMENT: invalid runtime metadata')
 public={'status':'DIAGNOSTIC_NOT_ACCEPTANCE','environment':environment,'sqlite_object_ordinal':1,'verifier_valid':probe['verifier_valid'],'verifier_codes':codes,'numeric_conversion_difference_observed':probe['numeric_conversion_difference_observed'],'original_bytes_unchanged':probe['original_unchanged']}
 print('::notice title=Baseline verifier diagnosis::'+json.dumps(public,sort_keys=True),flush=True)

 outputs = os.environ.get('GITHUB_OUTPUT')
 if outputs:
  with open(outputs, 'a', encoding='utf-8') as stream:
   stream.write('sqlite=' + environment['sqlite'] + '\n')
   stream.write('python=' + environment['python'] + '\n')
   stream.write('verifier_codes=' + (','.join(codes) or 'NONE') + '\n')
   stream.write('verifier_valid=' + ('true' if probe['verifier_valid'] else 'false') + '\n')
   stream.write('numeric_difference=' + ('true' if probe['numeric_conversion_difference_observed'] else 'false') + '\n')
