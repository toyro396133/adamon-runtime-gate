// Temporary, diagnostic-only source markers on the ephemeral private checkout.
// No assertions are changed; do not publish source, logs, or row data.
const fs=require('node:fs');
const path='src/services/knowledge-evidence.integration.test.ts';
let s=fs.readFileSync(path,'utf8');

const queryCleanupDependencies = [
"  // Ephemeral diagnostic: anonymous counts of FK rows preventing campaign cleanup.",
"  try {",
"    const fkMeta = await prisma.$queryRawUnsafe<Array<{rel: string; col: string}>>(",
"      'SELECT cl.relname AS rel, att.attname AS col FROM pg_constraint c ' +",
"      'JOIN pg_class cl ON cl.oid=c.conrelid ' +",
"      'JOIN pg_namespace ns ON ns.oid=cl.relnamespace ' +",
"      'JOIN pg_attribute att ON att.attrelid=c.conrelid AND att.attnum=c.conkey[1] ' +",
"      'WHERE c.contype=\\'f\\' AND c.confrelid=\\'public.\"Campaign\"\\'::regclass ' +",
"      'AND array_length(c.conkey,1)=1 AND ns.nspname=\\'public\\''",
"    );",
"    const qi = (v:string) => '\"' + v.replaceAll('\"','\"\"') + '\"';",
"    for (const r of fkMeta) {",
"      const found = await prisma.$queryRawUnsafe<Array<{n:number}>>(",
"        'SELECT count(*)::int AS n FROM '+qi(r.rel)+' WHERE '+qi(r.col)+' IN ($1,$2,$3)',",
"        campaign,next,id('foreign-c')",
"      );",
"      if (found[0]?.n) {",
"        const tag=createHash('sha256').update(r.rel).digest('hex').slice(0,8);",
"        process.stderr.write('KNOWLEDGE_BLOCKER_'+tag+'_'+found[0].n+'\\n');",
"      }",
"    }",
"  } catch {process.stderr.write('KNOWLEDGE_BLOCKER_DIAG_ERROR\\n');}",
].join("\\n") + "\\n  ";

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
if(!s.includes("await prisma.campaign.deleteMany"))throw Error('Campaign cleanup hook missing');
s=s.replace("await prisma.campaign.deleteMany",
  queryCleanupDependencies + "await prisma.campaign.deleteMany");
s="import { createHash } from 'node:crypto';\n"+s;
const runner='scripts/e2e/run-isolated-sql-suites.mjs';
let runnerSource=fs.readFileSync(runner,'utf8');
const anchor="if (phases.length) console.error('SQL suite ' + (index + 1) + '/' + suites.length + ': last known cleanup phase=' + phases.at(-1));";
if(!runnerSource.includes(anchor))throw Error('SQL cleanup reporter contract changed');
runnerSource=runnerSource.replace(anchor,anchor+"\n        const refs=[...hidden.matchAll(/KNOWLEDGE_BLOCKER_([a-f0-9]{8})_([0-9]{1,5})/g)].map(m=>m[1]+':'+m[2]);\n        if(refs.length)console.error('SQL suite '+(index+1)+'/'+suites.length+': anonymous blocker counts='+refs.join(','));");
fs.writeFileSync(runner,runnerSource);
fs.writeFileSync(path,s);
console.log('Knowledge teardown diagnostic markers applied to ephemeral checkout only.');
