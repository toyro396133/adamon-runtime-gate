// Summarize private Prisma migration SQL safely on a public runner.
// Never print SQL text, table names, column names, test data, or stack traces.
const fs = require('node:fs');
const file = process.argv[2];
let sql;
try { sql = fs.readFileSync(file, 'utf8'); }
catch { console.log('Schema diagnostic: DIFF_FILE_MISSING'); process.exit(2); }
const allowed = ['CreateTable','DropTable','AlterTable','CreateIndex','DropIndex',
  'AddForeignKey','DropForeignKey','CreateEnum','DropEnum','AlterEnum','AlterIndex',
  'RenameIndex','RenameTable','RedefineTables','AlterSequence'];
const headings = [...sql.matchAll(/^--\s+([A-Za-z]+)\s*$/gm)].map(m => m[1]);
const counts = {};
for (const action of headings) counts[action] = (counts[action] || 0) + 1;
const statements = (sql.match(/;\s*(?=\n|$)/g) || []).length;
const sqlType = {
  dropColumn: /\bDROP COLUMN\b/gi,
  addColumn: /\bADD COLUMN\b/gi,
  alterColumn: /\bALTER COLUMN\b/gi,
  dropConstraint: /\bDROP CONSTRAINT\b/gi,
  addConstraint: /\bADD CONSTRAINT\b/gi,
  dropIndex: /\bDROP INDEX\b/gi,
  createIndex: /\bCREATE (?:UNIQUE )?INDEX\b/gi,
  createTable: /\bCREATE TABLE\b/gi,
  dropTable: /\bDROP TABLE\b/gi,
  addForeignKey: /\bADD FOREIGN KEY\b/gi,
};
const details = Object.fromEntries(Object.entries(sqlType).map(([key, re]) => [key, [...sql.matchAll(re)].length]));
const unexpectedHeadings = headings.filter(x => !allowed.includes(x));
console.log('Schema diff safe summary: ' + JSON.stringify({statementCount:statements,headings:counts,operations:details,unknownHeadingCount:unexpectedHeadings.length,bytes:sql.length}));
if(sql.trim()==='' || sql.includes('-- This is an empty migration.')) console.log('Schema diagnostic: NO_DIFF');
else console.log('Schema diagnostic: DIFFERENCE_DETECTED (requires review; no automatic exemption)');
