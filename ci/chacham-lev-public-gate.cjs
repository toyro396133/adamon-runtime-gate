'use strict';
// Public, trusted gate: private stdout/stderr never enter the published summary.
// All strings printed below are constants. Input is exclusively numeric counters and enums.
const fs = require('node:fs');
const kinds = new Set(['smoke','unit','integration','schema']);
const [kind, file, exitText, secondsText] = process.argv.slice(2);
const integer = (v, max = 1000000) => Number.isSafeInteger(v) && v >= 0 && v <= max;
function reject(reason='STRUCTURE') {
  const code=['STRUCTURE','INPUT','MISSING','COUNTS','SUITES','CASES','EXIT','SCHEMA','CLONES','LENGTH','SUITE_SUM','CASE_SUM','SUCCESS_BOOL','NONZERO'].includes(reason)?reason:'STRUCTURE';
  console.error('Public evidence rejected: ' + code);
  process.exit(2);
}
if (!kinds.has(kind) || !/^(0|[1-9][0-9]{0,4})$/.test(exitText || '') ||
    !/^(0|[1-9][0-9]{0,5})$/.test(secondsText || '')) reject('INPUT');
let report;
try {
  if (fs.statSync(file).size > 16 * 1024 * 1024) reject();
  report = JSON.parse(fs.readFileSync(file,'utf8'));
} catch { reject('MISSING'); }
if (!report || typeof report !== 'object' || Array.isArray(report)) reject();
const rc = Number(exitText);
let counts;
if (kind === 'smoke' || kind === 'unit') {
  const keys = ['numTotalTestSuites','numPassedTestSuites','numFailedTestSuites',
    'numPendingTestSuites','numTotalTests','numPassedTests','numFailedTests','numPendingTests'];
  if (keys.some(k => !integer(report[k]) && !(k === 'numPendingTestSuites' && report[k] === undefined))) reject('COUNTS');
  if (report.numPendingTestSuites === undefined) report.numPendingTestSuites=0;
  const r = report;
  if (!Array.isArray(r.testResults) ||
      r.testResults.length < (kind === 'smoke' ? 20 : 176) ||
      r.testResults.length > r.numTotalTestSuites)
    reject('LENGTH');
  if (r.numTotalTestSuites === 0 || r.numTotalTests === 0) reject('NONZERO');
  if (r.numPassedTestSuites+r.numFailedTestSuites+r.numPendingTestSuites !== r.numTotalTestSuites)
    reject('SUITE_SUM');
  if (r.numPassedTests+r.numFailedTests+r.numPendingTests+(r.numTodoTests || 0) !== r.numTotalTests)
    reject('CASE_SUM');
  if (typeof r.success !== 'boolean') reject('SUCCESS_BOOL');
  for (const suite of r.testResults) {
    if (!suite || !['passed','failed','pending'].includes(suite.status) ||
        !Array.isArray(suite.assertionResults)) reject('SUITES');
    for (const a of suite.assertionResults) {
      if (!a || !['passed','failed','pending','skipped','todo','disabled'].includes(a.status)) reject('CASES');
    }
  }
  if ((rc === 0) !== (r.success === true && r.numFailedTests === 0 && r.numFailedTestSuites === 0)) reject('EXIT');
  counts = [r.testResults.length,r.numTotalTestSuites,r.numTotalTests,r.numPassedTests,r.numFailedTests,r.numPendingTests];
} else if(kind === 'integration') {
  if (report.version !== 1 || !integer(report.discoveredFiles) ||
      report.discoveredFiles < 11 || !integer(report.executedFiles) ||
      !integer(report.passedFiles) || !integer(report.failedFiles) ||
      !integer(report.passedCases) || !integer(report.failedCases) ||
      !integer(report.skippedCases) || !integer(report.cleanupSucceeded) ||
      !integer(report.cleanupFailed) ||
      report.passedFiles + report.failedFiles !== report.executedFiles ||
      report.executedFiles !== report.discoveredFiles ||
      report.cleanupSucceeded + report.cleanupFailed !== report.executedFiles ||
      report.passedCases + report.failedCases + report.skippedCases < report.executedFiles) reject('CLONES');
  if ((rc===0) !== (report.failedFiles===0 && report.failedCases===0 && report.skippedCases===0 &&
       report.cleanupFailed===0 && report.cleanupSucceeded===report.discoveredFiles)) reject('EXIT');
  counts = [report.discoveredFiles,report.executedFiles,report.passedCases,report.failedCases,report.skippedCases,report.cleanupSucceeded,report.cleanupFailed];
} else {
  if (report.version === 1 && report.status === 'FAIL') {
    const allowed = new Set(['MANIFEST_INVALID','MANIFEST_INVENTORY','MANIFEST_HASH',
      'CONTRACT_INCOMPLETE','PARITY_DRIFT','FOREIGN_KEY','CHECK_CONSTRAINT',
      'PARTIAL_UNIQUE','TRIGGER_DEFINITION','FUNCTION_DEFINITION','EXTRA_TRIGGER',
      'OTHER_PRIVATE_FAILURE']);
    console.error('Public schema rejection class: ' +
      (allowed.has(report.reason) ? report.reason : 'UNRECOGNIZED'));
    reject('SCHEMA');
  }
  if (report.version !== 1 || report.status !== 'PASS' ||
      !integer(report.migrations) || report.migrations < 1 ||
      !integer(report.foreignKeys) || report.foreignKeys < 1 ||
      !integer(report.triggers) || report.triggers < 1 ||
      !integer(report.unexpected) || report.unexpected !== 0 || rc !== 0) reject('SCHEMA');
  counts = [report.migrations,report.foreignKeys,report.triggers,report.unexpected];
}
console.log('- ' + kind + ': ' + (rc === 0 ? 'PASS' : 'FAIL') +
  ' exit=' + rc + ' seconds=' + Number(secondsText) +
  ' counts=' + counts.join('/'));
if (rc !== 0) process.exitCode = 1;
