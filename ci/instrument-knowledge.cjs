// Temporary, diagnostic-only source markers on the ephemeral private checkout.
// No assertions are changed; do not publish source, logs, or row data.
const fs=require('node:fs');
const path='src/services/knowledge-evidence.integration.test.ts';
let s=fs.readFileSync(path,'utf8');
const steps=[
['ASSIGN_EVENT','prisma.studentGroupAssignmentEvent.deleteMany'],
['ASSIGN','prisma.studentGroupAssignment.deleteMany'],
['ROUTE_AFFINITY','prisma.routeAffinity.deleteMany'],
['ROUTE_CONTINUITY','prisma.routeContinuityDecision.deleteMany'],
['ROUTE_DONOR','prisma.routeDonorLink.deleteMany'],
['ROUTE_CAMPAIGN','prisma.routeCampaign.deleteMany'],
['DONATION','prisma.donation.deleteMany'],
['PLEDGE','prisma.pledge.deleteMany'],
['CONNECTION','prisma.personConnection.deleteMany'],
['AUDIT','prisma.auditLog.deleteMany'],
['ADDRESS','prisma.address.deleteMany'],
['ROUTE','prisma.route.deleteMany'],
['GROUP','prisma.group.deleteMany'],
['CITY','prisma.city.deleteMany'],
['CAMPAIGN','prisma.campaign.deleteMany'],
['PERSON','prisma.person.deleteMany'],
['TENANT','prisma.tenant.deleteMany'],
['DISCONNECT','prisma.$disconnect()'],
];
for(const [label,anchor] of steps){
  const target='await '+anchor;
  if(!s.includes(target))throw Error('Knowledge fixture anchor mismatch');
  s=s.replace(target,"process.stderr.write('KNOWLEDGE_CLEANUP_"+label+"\\n');\n  "+target);
}
fs.writeFileSync(path,s);
console.log('Knowledge teardown diagnostic markers applied to ephemeral checkout only.');
