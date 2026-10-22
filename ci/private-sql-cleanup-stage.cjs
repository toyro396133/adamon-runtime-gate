// Opt-in, one-run instrumentation for the tenth private SQL integration suite.
// Only predefined stage numbers leave the ephemeral runner; no private paths,
// SQL, fixtures, column names, stack traces or test names are printed.
const fs = require('node:fs');
const path = require('node:path');
function find(directory) {
  return fs.readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
    const filename=path.join(directory,entry.name);
    return entry.isDirectory()?find(filename):entry.isFile()&&entry.name.endsWith('.integration.test.ts')?[filename]:[];
  }).sort();
}
const files=find('src');
if(files.length!==11)throw Error('Unexpected integration suite inventory');
const target=files[9];
let s=fs.readFileSync(target,'utf8');
const open=s.indexOf(' afterAll(async()=>{');
const close=s.indexOf('\n });\n it(',open);
if(open<0||close<open)throw Error('Cleanup structure changed');
let block=s.slice(open,close);
let count=0;
block=block.replace(/await prisma\.\$?\w+\.(?:deleteMany|delete)\(|await prisma\.\$disconnect\(/g,match=>{
  count++;
  return 'writeFileSync(process.env.RUNNER_TEMP + "/private-knowledge-stage", "STEP_' +
    String(count).padStart(2,'0') + '");' + match;
});
if(count<10||count>30)throw Error('Unexpected cleanup stages');
s="import { writeFileSync } from 'node:fs';\n"+s.slice(0,open)+block+s.slice(close);
fs.writeFileSync(target,s);
console.log('Ephemeral SQL cleanup stage instrumentation ready; '+count+' stages (no private paths).');
