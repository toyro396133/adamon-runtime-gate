"""Public CI infrastructure: numeric/hash evidence only, no private raw output."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

HEAD='d7cd7cc9061747344ca4565d7e3ef1f8ed7c7679'
root=Path(sys.argv[1]).resolve()
raw=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'adamon-private-evidence'
raw.mkdir(mode=0o700,parents=True,exist_ok=False)
output=raw/'artifacts'
env={k:v for k,v in os.environ.items() if not any(x in k.upper() for x in ('TOKEN','SECRET','PASSWORD'))}
env['PYTHONPATH']=str(root)
summary={'SOURCE_HEAD':HEAD,'FINAL_STATUS':'M2_NOT_VERIFIED','HELD_OUT_GENERALISATION':'PENDING',
 'scope_marker':'HELD_OUT_GENERALISATION_PENDING','M3':'NOT_STARTED','BLOCKER_CLASS':'NONE',
 'runtime_run_id':os.environ.get('GITHUB_RUN_ID'),'runtime_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
 'infrastructure_head':os.environ.get('GITHUB_SHA'),'artifacts':{},'RAW_EVIDENCE':'PRIVATE_RUNNER_ONLY'}

def run(label,args):
    print(label+': START',flush=True)
    start=time.monotonic();seen=set()
    with (raw/(label+'.log')).open('wb') as f:
        p=subprocess.Popen(args,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT)
        while True:
            try:code=p.wait(timeout=30);break
            except subprocess.TimeoutExpired:
                print(label+': RUNNING elapsed_seconds='+str(int(time.monotonic()-start)),flush=True)
                for line in (raw/(label+'.log')).read_text(errors='replace').splitlines():
                    if re.fullmatch(r'PROGRESS [a-z0-9_]+ (START|END exit=[0-9]+)',line) and line not in seen:
                        print(line,flush=True);seen.add(line)
    for line in (raw/(label+'.log')).read_text(errors='replace').splitlines():
        if re.fullmatch(r'PROGRESS [a-z0-9_]+ (START|END exit=[0-9]+)',line) and line not in seen:print(line,flush=True)
    (raw/(label+'.exit')).write_text(str(code)+'\n')
    summary[label]={'exit':code,'elapsed_seconds':round(time.monotonic()-start,2),
       'log_sha256':hashlib.sha256((raw/(label+'.log')).read_bytes()).hexdigest(),
       'exit_sha256':hashlib.sha256((raw/(label+'.exit')).read_bytes()).hexdigest()}
    print(label+': END exit='+str(code),flush=True)
    return code

try:
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root).decode().strip()==HEAD
    assert sys.version_info[:2]==(3,12)
    assert run('dependencies',[sys.executable,'-m','pip','install','-r','requirements-tested.txt','-e','.'])==0
    code=run('m214_protocol',[sys.executable,'-m','scripts.run_m2_final_closure','--directory',str(raw/'protocol'),
            '--output-dir',str(output),'--candidate',HEAD])
    assert code==0
    certificate=json.loads((output/'gen0_5A_M2_m214_closure_certificate.json').read_text())
    assert certificate['FINAL_STATUS']=='M2_VERIFIED' and certificate['candidate_sha']==HEAD
    assert certificate['full_run_a']['passed']==certificate['full_run_b']['passed']==624
    assert certificate['tier3']['passed']==395 and certificate['source_preservation']==certificate['package_preservation']=='PASS'
    summary.update({'FINAL_STATUS':'M2_VERIFIED','TIER3':certificate['tier3'],
       'FULL_RUN_A':certificate['full_run_a'],'FULL_RUN_B':certificate['full_run_b'],
       'REPLAY_COMPARISON':certificate['replay_comparison'],'SOURCE_PRESERVATION':'PASS','PACKAGE_PRESERVATION':'PASS',
       'VERIFIER_BYTE_PRESERVATION':'PASS','CLOSE_REOPEN':'PASS','environment':certificate['environment']})
except Exception:
    summary['BLOCKER_CLASS']='FINAL_CLOSURE_PROTOCOL_FAILED'

# JSON artifacts have hashed fixture identifiers, numeric measurements and statuses.
# Never upload pytest logs, SQLite files, private source or the private replay report.
allowed=['gen0_5A_M2_m214_replay_comparison.json','gen0_5A_M2_m214_m1_measurements.json',
 'gen0_5A_M2_m214_measurements.json','gen0_5A_M2_results.json','gen0_5A_M2_m214_closure_certificate.json',
 'source_manifest.json','package_manifest.json']
token=os.environ.get('EVIDENCE_TOKEN')

def publish(name,data):
    payload=json.dumps({'message':'docs: retain M2.14 numeric closure evidence','content':base64.b64encode(data).decode(),'branch':'main'}).encode()
    url='https://api.github.com/repos/toyro396133/adamon-runtime-gate/contents/evidence/m214/'+HEAD+'/'+name
    req=urllib.request.Request(url,data=payload,method='PUT',headers={'Authorization':'Bearer '+token,
         'Accept':'application/vnd.github+json','Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:assert response.status==201

try:
    assert token
    for name in allowed:
        path=output/name
        if path.is_file():
            data=path.read_bytes();publish(name,data)
            summary['artifacts'][name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    publish('summary.json',(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode())
    print('numeric_certificates: SAVED',flush=True)
except Exception:
    print('numeric_certificates: SAVE_FAILED',flush=True)
    raise SystemExit(1)
text=json.dumps(summary,indent=2,sort_keys=True)
print(text,flush=True)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:f.write('```json\n'+text+'\n```\n')
raise SystemExit(0 if summary['FINAL_STATUS']=='M2_VERIFIED' else 1)
