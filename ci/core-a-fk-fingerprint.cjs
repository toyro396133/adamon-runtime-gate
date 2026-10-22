// Reads only the disposable loopback test DB. Prints table hashes and counts,
// never private table/column names, source snippets, or row data.
const path=require('node:path');
const {createRequire}=require('node:module');
const {Client}=createRequire(path.resolve('package.json'))('pg');
function hash(s){let h=0x811c9dc5;for(let i=0;i<s.length;i++)h=Math.imul(h^s.charCodeAt(i),0x01000193)>>>0;return h.toString(16).padStart(8,'0');}
function quote(s){return '"' + String(s).replace(/"/g,'""') + '"';}
(async()=>{
  const u=new URL(process.env.DATABASE_URL||'');
  if(!['localhost','127.0.0.1'].includes(u.hostname) || !/^chacham_lev_test_[0-9]+$/.test(u.pathname.slice(1)))throw Error('Only isolated DB allowed');
  const db=new Client({connectionString:u.toString()});
  await db.connect();
  try{
    const meta=await db.query(
      'SELECT c.conrelid::regclass::text AS tbl,a.attname AS col, n.nspname AS ns, cl.relname AS rel '+
      'FROM pg_constraint c JOIN pg_class cl ON cl.oid=c.conrelid '+
      'JOIN pg_namespace n ON n.oid=cl.relnamespace '+
      'JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1] '+
      'WHERE c.contype=\'f\' AND c.confrelid=\'public."Person"\'::regclass '+
      'AND array_length(c.conkey,1)=1 AND n.nspname=\'public\''
    );
    const matches=[];
    for(const row of meta.rows){
      const q='SELECT count(*)::int AS n FROM '+quote(row.ns)+'.'+quote(row.rel)+
        ' child JOIN "Person" p ON child.'+quote(row.col)+'=p.id WHERE p."tenantId" LIKE \'core-a-%\'';
      try{const count=(await db.query(q)).rows[0].n;if(count>0)matches.push({id:hash(row.rel),count});}
      catch{/* never log SQL text or a private table name */}
    }
    const tenancy=(await db.query(
      'SELECT count(*) FILTER (WHERE c."tenantId"=p."tenantId")::int AS matching, '+
      'count(*) FILTER (WHERE c."tenantId"<>p."tenantId")::int AS mismatching '+
      'FROM "ContactCoordination" c JOIN "Person" p ON p.id=c."personId" '+
      'WHERE p."tenantId" LIKE \'core-a-%\''
    )).rows[0];
    const guard=(await db.query(
      'SELECT count(*)::int AS n FROM pg_trigger WHERE tgname=\'scope_ContactCoordination\' AND NOT tgisinternal'
    )).rows[0].n;
    console.log('Core A synthetic Person FK blockers: '+JSON.stringify(matches));
    console.log('Core A ContactCoordination synthetic scope: '+JSON.stringify({matching:tenancy.matching,mismatching:tenancy.mismatching,guardPresent:guard>0}));
  }finally{await db.end();}
})().catch(()=>{console.log('Core A FK fingerprint UNAVAILABLE');process.exitCode=1;});
