'use strict';
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const {mkdtempSync,writeFileSync,rmSync}=require('node:fs');
const {join}=require('node:path');
const {tmpdir}=require('node:os');
const path=join(__dirname,'chacham-lev-public-gate.cjs');
const dir=mkdtempSync(join(tmpdir(),'safe-public-evidence-'));
const secret='SYNTHETIC_PRIVATE_PATH_AND_TOKEN_NEVER_PUBLISH';
function run(kind,report,rc='0') {
  const file=join(dir,'private.json');
  writeFileSync(file,JSON.stringify(report));
  const p=spawnSync(process.execPath,[path,kind,file,rc,'4'],{encoding:'utf8'});
  assert.equal((p.stdout+p.stderr).includes(secret),false,'private payload appeared in public output');
  return p;
}
function fixture(n) {
  return {success:true,numTotalTestSuites:n,numPassedTestSuites:n,numFailedTestSuites:0,
    numPendingTestSuites:0,numTotalTests:n,numPassedTests:n,numFailedTests:0,
    numPendingTests:0,testResults:Array.from({length:n},()=>({name:secret,status:'passed',
      message:secret,assertionResults:[{status:'passed',fullName:secret}]})),
    privateExtraField:secret};
}
const valid=fixture(180);
const smoke=fixture(20);
try{
  assert.equal(run('unit',valid).status,0,'valid strict aggregate rejected');
  assert.equal(run('smoke',smoke).status,0,'valid smoke suite rejected');
  assert.equal(run('unit',{...valid,numPassedTests:secret}).status,2,'malicious numeric field not rejected');
  assert.equal(run('unit',{...valid,numPassedTests:1,numFailedTests:1}).status,2,'inconsistent counts not rejected');
  assert.equal(run('smoke',{...smoke,testResults:[]}).status,2,'missing suite evidence not rejected');
  assert.equal(run('unit',{...valid,success:false},'0').status,2,'afterAll failure claimed success');
  const teardown={...valid,success:false,numFailedTestSuites:1,numPassedTestSuites:179,
    testResults:valid.testResults.map((r,i)=>i===0?{...r,status:'failed'}:r)};
  assert.equal(run('unit',teardown,'1').status,1,
    'legitimate teardown failure not reported as failure');
  assert.equal(run('integration',{version:1,discoveredFiles:11,executedFiles:11,
    passedFiles:11,failedFiles:0,passedCases:210,failedCases:0,
    skippedCases:0,cleanupSucceeded:11,cleanupFailed:0}).status,0);
  assert.equal(run('integration',{version:1,discoveredFiles:11,executedFiles:11,
    passedFiles:11,failedFiles:0,passedCases:210,failedCases:0,
    skippedCases:0,cleanupSucceeded:10,cleanupFailed:1}).status,2,
    'clone cleanup failure accepted');
  assert.equal(run('schema',{version:1,status:'PASS',migrations:21,foreignKeys:91,
    triggers:42,unexpected:0}).status,0);
  assert.equal(run('schema',{version:1,status:secret,migrations:21,foreignKeys:91,
    triggers:42,unexpected:0}).status,2,'untrusted status accepted');
  console.log('Public summary gate: positive and adversarial synthetic fixtures PASS');
}finally{rmSync(dir,{force:true,recursive:true});}
