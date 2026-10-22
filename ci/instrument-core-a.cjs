// Diagnostic-only markers. This file never stores the private source content.
// Applied to an ephemeral checkout only for the opt-in corea diagnostic tier.
// No statements are skipped or assertions changed.
const { readFileSync, writeFileSync } = require('node:fs');
const file = 'src/actions/core-a.integration.test.ts';
let source = readFileSync(file, 'utf8');
const steps = [
  ['TENANT', 'await prisma.tenant.createMany('],
  ['USER', 'await prisma.user.createMany('],
  ['CAMPAIGN', 'await prisma.campaign.createMany('],
  ['PERSON', 'await prisma.person.create('],
  ['READY', 'state.userId = master;'],
];
for (const [label, anchor] of steps) {
  if (!source.includes(anchor)) throw new Error('Core A diagnostic hook mismatch');
  source = source.replace(anchor, "process.stderr.write('CORE_A_PHASE_" + label + "\\n');\n    " + anchor);
}
writeFileSync(file, source);
console.log('Core A ephemeral fixture-stage markers installed (no source published).');
