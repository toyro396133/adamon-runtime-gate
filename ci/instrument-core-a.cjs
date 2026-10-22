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

const cleanup = [
  ['AUDIT', 'await prisma.auditLog.deleteMany('],
  ['DONATIONS', 'await prisma.donation.deleteMany('],
  ['PERSON_LINK', 'await prisma.userPersonLink.deleteMany('],
  ['PERSON_LINK_EVENT', 'await prisma.userPersonLinkEvent.deleteMany('],
  ['STUDENT_ASSIGN_EVENT', 'await prisma.studentGroupAssignmentEvent.deleteMany('],
  ['STUDENT_ASSIGN', 'await prisma.studentGroupAssignment.deleteMany('],
  ['ROUTE_DONOR', 'await prisma.routeDonorLink.deleteMany('],
  ['ROUTE_CAMPAIGN', 'await prisma.routeCampaign.deleteMany('],
  ['ROUTE', 'await prisma.route.deleteMany('],
  ['GROUP', 'await prisma.group.deleteMany('],
  ['ADDRESS', 'await prisma.address.deleteMany('],
  ['PERSON', 'await prisma.person.deleteMany('],
  ['CAMPAIGN', 'await prisma.campaign.deleteMany('],
  ['USER', 'await prisma.user.deleteMany('],
  ['TENANT', 'await prisma.tenant.deleteMany('],
  ['DISCONNECT', 'await prisma.$disconnect()'],
];
for (const [label, anchor] of cleanup) {
  if (!source.includes(anchor)) throw new Error('Core A cleanup diagnostic hook mismatch');
  source = source.replace(anchor, "process.stderr.write('CORE_A_CLEANUP_" + label + "\\n');\n    " + anchor);
}

writeFileSync(file, source);
console.log('Core A ephemeral fixture-stage markers installed (no source published).');
