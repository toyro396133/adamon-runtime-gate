// Publish only aggregate test status and stable, anonymous suite IDs.
// Never emit Vitest failure strings, stack traces, test titles or source code.
const fs = require('node:fs');
const [reportPath, label] = process.argv.slice(2);
function hash(input) {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h = Math.imul(h ^ input.charCodeAt(i), 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}
function safeSignature(text) {
  const types = ['PrismaClientKnownRequestError', 'PrismaClientUnknownRequestError',
    'PrismaClientValidationError', 'PrismaClientInitializationError',
    'TypeError', 'ReferenceError', 'SyntaxError', 'AssertionError', 'AggregateError'];
  const type = types.find(name => text.includes(name)) || 'UNCLASSIFIED';
  const codes = [...new Set(text.match(/\bP[123]\d{3}\b/g) || [])].slice(0, 3);
  const stage = /beforeAll/i.test(text) ? 'BEFORE_ALL'
    : /afterAll/i.test(text) ? 'AFTER_ALL' : 'UNKNOWN_STAGE';
  return [type, stage, ...(codes.length ? codes : ['NO_PRISMA_CODE'])].join('/');
}
function classify(text) {
  if (/P20\d{2}|P10\d{2}/.test(text)) return 'DATABASE_PRISMA';
  if (/relation .* does not exist|column .* does not exist|unknown field|unknown argument/i.test(text)) return 'SCHEMA';
  if (/foreign key|unique constraint/i.test(text)) return 'CONSTRAINT';
  if (/ECONNREFUSED|connect ECONN|database.*unavailable/i.test(text)) return 'CONNECTION';
  if (/timeout|timed out/i.test(text)) return 'TIMEOUT';
  if (/cannot find module|failed to resolve|failed to load/i.test(text)) return 'IMPORT';
  if (/AssertionError|expected .* to /i.test(text)) return 'ASSERTION';
  if (/beforeAll|beforeEach|afterAll|test setup/i.test(text)) return 'FIXTURE';
  return 'OTHER';
}
try {
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  const suites = report.testResults || [];
  const bad = suites.filter(suite => suite.status === 'failed');
  const counts = [
    ['suites', report.numTotalTestSuites],
    ['passed', report.numPassedTestSuites],
    ['failed', report.numFailedTestSuites],
    ['tests', report.numTotalTests],
    ['failedTests', report.numFailedTests],
    ['pendingTests', report.numPendingTests],
  ].map(([k,v]) => k + '=' + (Number.isFinite(v) ? v : '?')).join(' ');
  console.log('- ' + label + ' aggregate: ' + counts);
  for (const suite of bad.slice(0, 25)) {
    const name = String(suite.name || '');
    const relative = name.includes('/source/') ? name.split('/source/').pop() : name.split('/').slice(-2).join('/');
    const messages = [suite.message, suite.failureMessage, suite.errorMessage,
      ...(suite.assertionResults || []).flatMap(a => a.failureMessages || [])].filter(Boolean).join('\n');
    const assertions = (suite.assertionResults || []).filter(a => a.status === 'failed');
    console.log('- ' + label + ' failing ID: ' + hash(relative) + ' / ' + classify(messages) +
      ' / cases=' + assertions.length + ' / ' + safeSignature(messages));
    for (const a of assertions.slice(0, 8)) {
      const failure = (a.failureMessages || []).join('\\n');
      console.log('- ' + label + ' failing case ID: ' + hash(relative + ':' + String(a.fullName || a.title || '')) +
        ' / ' + classify(failure));
    }
  }
  if (bad.length > 25) console.log('- ' + label + ' additional failed suites omitted: ' + (bad.length - 25));
} catch {
  console.log('- ' + label + ' aggregate: NOT_AVAILABLE (private diagnostics withheld)');
}
