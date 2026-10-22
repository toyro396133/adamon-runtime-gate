// Diagnostic-only, ephemeral instrumentation. The helper modifies a private
// checkout inside a disposable CI job; only fixed error codes are printed.
const fs=require('node:fs');
const file='src/services/knowledge-evidence.integration.test.ts';
let s=fs.readFileSync(file,'utf8');
const before="await prisma.campaign.deleteMany({where:{tenantId:{in:[tenant,other]}}});";
if(!s.includes(before))throw Error('Fixture contract changed');
s=s.replace(before, [
"try {",
"  "+before,
"} catch (error) {",
"  const code=typeof error?.code==='string' && /^P[12][0-9]{3}$/.test(error.code)?error.code:'UNKNOWN';",
"  process.stderr.write('KNOWLEDGE_CAMPAIGN_ERROR_'+code+'\\n');",
"  throw error;",
"}",
].join("\n"));
fs.writeFileSync(file,s);
const runner='scripts/e2e/run-isolated-sql-suites.mjs';
let src=fs.readFileSync(runner,'utf8');
const anchor="const category = /foreign key|P2003|23503/i.test(hidden)";
if(!src.includes(anchor))throw Error('SQL reporter changed');
src=src.replace(anchor,
"const cleanupCodes=[...hidden.matchAll(/KNOWLEDGE_CAMPAIGN_ERROR_(P[12][0-9]{3}|UNKNOWN)/g)].map(m=>m[1]);\n"+
"        if(cleanupCodes.length)console.error('SQL cleanup Prisma code='+cleanupCodes.at(-1));\n"+
"        "+anchor);
fs.writeFileSync(runner,src);
console.log('Ephemeral fixed-code diagnostic prepared; no private source or row data published.');
