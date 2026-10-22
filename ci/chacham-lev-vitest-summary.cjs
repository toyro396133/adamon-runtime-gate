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

// The runner's private Vitest log is read only inside the ephemeral job.
// Output MUST remain a fixed vocabulary: never log the input text or paths.
function privateLogFingerprint(label) {
  let raw = '';
  try {
    raw = fs.readFileSync(process.env.RUNNER_TEMP + '/private-' + label + '.log', 'utf8');
  } catch {
    return 'LOG_UNAVAILABLE';
  }
  const marks = {
    PRISMA_P2002: /P2002|Unique constraint failed/i,
    PRISMA_P2003: /P2003|Foreign key constraint failed/i,
    PRISMA_P2022: /P2022|column .* does not exist/i,
    PRISMA_P2021: /P2021|table .* does not exist/i,
    DATABASE_DRIVER: /P1001|P1000|ECONNREFUSED|connection terminated/i,
    DB_UNIQUE_INDEX: /Campaign_one_active_operational_per_tenant/i,
    IMPORT_RESOLVE: /Cannot find module|Failed to resolve import/i,
    MOCK_ERROR: /No .* export is defined on the .* mock|vi\.mock|\[vitest\]/i,
    TYPE_ERROR: /TypeError:|Cannot read properties of/i,
    REFERENCE_ERROR: /ReferenceError:/i,
    HOOK_TIMEOUT: /Hook timed out|beforeAll hook timed out|afterAll hook timed out/i,
    SETUP_HOOK: /beforeAll|before each|beforeEach/i,
    TEARDOWN_HOOK: /afterAll|after each|afterEach/i,
    UNHANDLED: /unhandled rejection|unhandled error/i,
    SQLITE: /sqlite/i,
  };
  const marker = [...raw.matchAll(/CORE_A_PHASE_(TENANT|USER|CAMPAIGN|PERSON|READY)/g)].map(m => m[1]).at(-1);
  if (marker) console.log('- ' + label + ' Core A last setup stage: ' + marker);
  const cleanup = [...raw.matchAll(/CORE_A_CLEANUP_(AUDIT|DONATIONS|PERSON_LINK|PERSON_LINK_EVENT|STUDENT_ASSIGN_EVENT|STUDENT_ASSIGN|ROUTE_DONOR|ROUTE_CAMPAIGN|ROUTE|GROUP|ADDRESS|PERSON|CAMPAIGN|USER|TENANT|DISCONNECT)/g)].map(m => m[1]);
  if (cleanup.length) console.log('- ' + label + ' Core A last teardown stage: ' + cleanup.at(-1));
  const found = Object.entries(marks).filter(([, regex]) => regex.test(raw)).map(([k]) => k);
  return found.length ? found.join(',') : 'OTHER_LOG_SIGNATURE';
}


function nestedErrorEvidence(node, depth = 0, field = 'root', visited = new Set()) {
  if (depth > 6 || node == null) return { strings: [], paths: [] };
  if (typeof node === 'string') {
    if (/error|message|failure|reason|stack/i.test(field)) return { strings: [node], paths: [field + ':string'] };
    return { strings: [], paths: [] };
  }
  if (typeof node !== 'object' || visited.has(node)) return { strings: [], paths: [] };
  visited.add(node);
  const out = { strings: [], paths: [] };
  const entries = Array.isArray(node) ? node.map((value, i) => [String(i), value]) : Object.entries(node);
  for (const [key, value] of entries) {
    if (out.strings.length >= 60 || out.paths.length >= 60) break;
    const path = field + '.' + (Array.isArray(node) ? 'item' : key);
    if (typeof value === 'string' && /error|message|failure|reason|stack/i.test(path)) {
      out.strings.push(value);
      out.paths.push(path + ':string');
    } else if (typeof value === 'object' && value !== null) {
      const nested = nestedErrorEvidence(value, depth + 1, path, visited);
      out.strings.push(...nested.strings);
      out.paths.push(...nested.paths);
    }
  }
  return out;
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
    ['passedTests', report.numPassedTests],
    ['failed', report.numFailedTestSuites],
    ['tests', report.numTotalTests],
    ['failedTests', report.numFailedTests],
    ['pendingTests', report.numPendingTests],
  ].map(([k,v]) => k + '=' + (Number.isFinite(v) ? v : '?')).join(' ');
  console.log('- ' + label + ' aggregate: ' + counts);
  if (bad.length) console.log('- ' + label + ' sanitized private-log signature: ' + privateLogFingerprint(label));
  for (const suite of bad.slice(0, 25)) {
    const name = String(suite.name || '');
    const relative = name.includes('/source/') ? name.split('/source/').pop() : name.split('/').slice(-2).join('/');
    const nested = nestedErrorEvidence(suite);
    const messages = [suite.message, suite.failureMessage, suite.errorMessage,
      ...nested.strings].filter(Boolean).join('\n');
    console.log('- ' + label + ' error field paths: ' + [...new Set(nested.paths)].slice(0, 12).join(','));

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
