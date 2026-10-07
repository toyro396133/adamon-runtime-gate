"""Public SELF gate bridge: private logs, numeric/hash-only public evidence."""
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

HEAD='82c8264cd469797470b1ff55e1ad9106fbfa41ea'
BRANCH='work/m3-heldout-round1-20261007'
root=Path(sys.argv[1]).resolve()
raw=Path(os.environ['RUNNER_TEMP'])/'adamon-self-private-evidence'
raw.mkdir(mode=0o700, parents=True, exist_ok=False)
out=raw/'protocol'
env={k:v for k,v in os.environ.items() if not any(x in k.upper() for x in ('TOKEN','SECRET','PASSWORD'))}
env['PYTHONPATH']=str(root)
env['PYTHONDONTWRITEBYTECODE']='1'
summary={'SOURCE_HEAD':HEAD, 'FINAL_STATUS':'SELF_NOT_VERIFIED',
 'M3':'PAUSED_CLEAN_BEFORE_MATERIALIZATION', 'numeric_seed_derived':False,
 'heldout_bundle_materialized':False, 'oracle_generated':False,
 'production_evaluation_started':False, 'semantic_heldout_results_exposed':False,
 'runtime_run_id':os.environ.get('GITHUB_RUN_ID'),'runtime_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
 'infrastructure_head':os.environ.get('GITHUB_SHA'),'artifacts':{}}

def run(label,args):
    print(label+': START',flush=True)
    start=time.monotonic(); seen=set()
    log=raw/(label+'.log')
    with log.open('wb') as handle:
        p=subprocess.Popen(args,cwd=root,env=env,stdout=handle,stderr=subprocess.STDOUT)
        while True:
            try: code=p.wait(timeout=30);break
            except subprocess.TimeoutExpired:
                print(label+': RUNNING elapsed_seconds='+str(int(time.monotonic()-start)),flush=True)
                for line in log.read_text(errors='replace').splitlines():
                    if re.fullmatch(r'(PROGRESS [a-z0-9_]+ (START|END exit=[0-9]+)|HEARTBEAT [a-z0-9_]+ [0-9]+)',line) and line not in seen:
                        print(line,flush=True);seen.add(line)
    for line in log.read_text(errors='replace').splitlines():
        if re.fullmatch(r'(PROGRESS [a-z0-9_]+ (START|END exit=[0-9]+)|HEARTBEAT [a-z0-9_]+ [0-9]+)',line) and line not in seen:
            print(line,flush=True)
    (raw/(label+'.exit')).write_text(str(code)+'\n')
    summary[label]={'exit':code,'elapsed_seconds':round(time.monotonic()-start,2),
      'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
    print(label+': END exit='+str(code),flush=True)
    return code

def publish(repo,branch,path,data,token):
    req=urllib.request.Request('https://api.github.com/repos/'+repo+'/contents/'+path,
      data=json.dumps({'message':'docs: retain SELF closure evidence','branch':branch,
        'content':base64.b64encode(data).decode()}).encode(),method='PUT',
      headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:
        if response.status!=201:raise ValueError('evidence publication failed')

try:
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root).decode().strip()==HEAD
    assert run('dependencies',[sys.executable,'-m','pip','install','-r','requirements-tested.txt','-e','.'])==0
    code=run('self_protocol',[sys.executable,'-m','scripts.run_self_mvp_gate','--candidate',HEAD,'--directory',str(out)])
    certificate=json.loads((out/'self_closure_certificate.json').read_text())
    summary['certificate_status']=certificate['status']
    if code==0 and certificate['status']=='SELF_VERIFIED':
        assert certificate['clusters']['self_focused']['passed']==35
        assert certificate['clusters']['repository_full']['passed']==659
        assert certificate['source_preservation']==certificate['package_preservation']=='PASS'
        assert certificate['verifier_byte_preservation']=='PASS'
        summary['FINAL_STATUS']='SELF_VERIFIED'
except Exception:
    summary['BLOCKER_CLASS']='SELF_CLOSURE_PROTOCOL_FAILED'

# On failure retain exact private pytest/nodeid/traceback evidence in the source
# branch when the source token permits contents writes; never emit it publicly.
if summary['FINAL_STATUS']!='SELF_VERIFIED':
    try:
        private=os.environ['PRIVATE_EVIDENCE_TOKEN']
        import io,zipfile
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for path in raw.rglob('*'):
                if path.is_file() and path.suffix in ('.log','.xml','.exit','.json'):
                    z.write(path,str(path.relative_to(raw)))
        publish('toyro396133/cognitive-zero',BRANCH,'docs/self_mvp_ci/'+HEAD+'/failure-evidence.zip',
                archive.getvalue(),private)
        summary['private_failure_evidence']='SAVED'
    except Exception:
        summary['private_failure_evidence']='SAVE_BLOCKED'

token=os.environ['EVIDENCE_TOKEN']
for name in ('self_closure_certificate.json','source_manifest.json','package_manifest.json','byte_audits.json'):
    path=out/name
    if path.is_file():
        data=path.read_bytes()
        publish('toyro396133/adamon-runtime-gate','main','evidence/self/'+HEAD+'/'+name,data,token)
        summary['artifacts'][name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
publish('toyro396133/adamon-runtime-gate','main','evidence/self/'+HEAD+'/summary.json',
        (json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(),token)
print(json.dumps(summary,indent=2,sort_keys=True),flush=True)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:
        f.write('SELF closure: '+summary['FINAL_STATUS']+'; source '+HEAD+'\n')
raise SystemExit(0 if summary['FINAL_STATUS']=='SELF_VERIFIED' else 1)
