/**
 * Isolated end-to-end browser checks for actual merged I3 application code.
 * The whole database contains SYNTHETIC fixtures only. Real NextAuth credentials,
 * real PostgreSQL 16, production-mode Next.js and real Chromium; no response mocks.
 */
import {test,expect,type Page} from '@playwright/test';

const password=process.env.E2E_TEST_PASSWORD || '';
const phone={
  admin:'052-1234507',
  collector:'052-1234501',
  foreignCollector:'052-1234599',
};
async function login(page:Page,role:keyof typeof phone) {
  if(!password) throw Error('SYNTHETIC_E2E_PASSWORD_REQUIRED');
  await page.goto('/login');
  await page.getByLabel('מספר טלפון').fill(phone[role]);
  await page.getByLabel('סיסמה').fill(password);
  await page.getByRole('button',{name:'התחבר',exact:true}).click();
  await page.waitForURL('**/dashboard',{timeout:20000});
}
async function openPerson(page:Page,name:string) {
  await page.goto('/people');
  const open=page.getByRole('button',{name:'פרטי '+name});
  await expect(open).toBeVisible({timeout:25000});
  await open.click();
  const dialog=page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  return dialog;
}

test('admin: authenticated people card shows empty canonical institution and no inferred relations; reload persists',async({page})=>{
  await login(page,'admin');
  let dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
  await dialog.getByRole('button',{name:'קשרים',exact:true}).click();
  await expect(dialog.getByText('אין עדיין זיקות מאומתות להצגה.')).toBeVisible();
  await dialog.getByRole('button',{name:'מיפוי Active'}).click();
  await expect(dialog.getByText('סטטוס Active — מקור ומיפוי מוצע')).toBeVisible();
  await expect(dialog.getByText('כרטיס מקור:',{exact:false})).toBeVisible();
  await expect(page.locator('body')).not.toContainText('UNVERIFIED_PRIVATE');
  await page.reload();
  dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
});

test('authenticated collector cannot assert an institutional fact; no silent authorization grant',async({page})=>{
  await login(page,'collector');
  const dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
  await dialog.getByLabel('מקור ואסמכתה').fill('SYNTHETIC-UNTRUSTED');
  await dialog.getByLabel('נימוק ואימות עדכניות').fill('Testing write rejection only');
  await dialog.getByRole('button',{name:'שמור הכרעה ידנית'}).click();
  // Next.js production Server Actions deliberately redact the exact server-side
  // Forbidden reason; the UI must show a safe error without source disclosure.
  await expect(dialog.getByRole('alert')).toBeVisible({timeout:20000});
  await expect(dialog.getByRole('alert')).not.toContainText('SYNTHETIC-UNTRUSTED');
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
  await page.reload();
  const after=await openPerson(page,'תורם בדיקה');
  await after.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(after.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
});

test('foreign tenant logged-in collector cannot see first tenant person, even after reload',async({page})=>{
  await login(page,'foreignCollector');
  await page.goto('/people');
  await expect(page.getByRole('button',{name:'פרטי תורם מוסד זר'})).toBeVisible({timeout:25000});
  await expect(page.getByRole('button',{name:'פרטי תורם בדיקה'})).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole('button',{name:'פרטי תורם בדיקה'})).toHaveCount(0);
});

test('person A to B switching clears A evidence and relations, retains server-authenticated session',async({page})=>{
  await login(page,'admin');
  let dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'מיפוי Active'}).click();
  await expect(dialog.getByText('כרטיס מקור:',{exact:false})).toBeVisible();
  await dialog.getByRole('button',{name:'סגור חלון'}).click();
  const next=page.getByRole('button',{name:'פרטי תורם ללא טלפון'});
  await expect(next).toBeVisible({timeout:20000});
  await next.click();
  dialog=page.getByRole('dialog');
  await dialog.getByRole('button',{name:'מיפוי Active'}).click();
  await expect(dialog.getByText('לא קיימת הצלבת I3 מאומתת עבור אדם זה.')).toBeVisible();
  await expect(dialog.getByText('כרטיס מקור:',{exact:false})).toHaveCount(0);
});

test('anonymous user cannot see canonical people or unverified source evidence',async({page})=>{
  await page.goto('/people');
  await expect(page.getByRole('button',{name:'פרטי תורם בדיקה'})).toHaveCount(0);
  await page.goto('/people/source-evidence?tenantId=e2e-mobile-tenant&sourceKey=1');
  await expect(page.locator('body')).not.toContainText('UNVERIFIED_PRIVATE');
});


test('admin: semantic education status is a separate canonical dimension from legacy source',async({page})=>{
  await login(page,'admin');
  const dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'מצב לימודי'}).click();
  await expect(dialog.getByText('מצב תקף:',{exact:false})).toBeVisible();
  await expect(dialog.getByText('ראיות מהייבוא:',{exact:false})).toBeVisible();
  await expect(page.locator('body')).not.toContainText('UNVERIFIED_PRIVATE');
});

test('admin: synthetic institutional decision validates period, persists with real database readback and audit',async({page})=>{
  await login(page,'admin');
  let dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
  await dialog.getByLabel('מקור ואסמכתה').fill('SYNTHETIC_FIXTURE_VERIFIED');
  await dialog.getByLabel('נימוק ואימות עדכניות').fill('Synthetic-only operator-approved enrollment; no real identities');
  await dialog.locator('input[name="validFrom"]').fill('2027-05-02');
  await dialog.locator('input[name="validUntil"]').fill('2027-04-01');
  await dialog.getByRole('button',{name:'שמור הכרעה ידנית'}).click();
  // Invalid periods must fail closed, even though Next.js redacts the actual
  // server exception message in its production-mode Server Action response.
  await expect(dialog.getByRole('alert')).toBeVisible({timeout:20000});
  await expect(dialog.getByText('אין שיוכים שנקבעו ידנית.')).toBeVisible();
  await dialog.locator('input[name="validFrom"]').fill('');
  await dialog.locator('input[name="validUntil"]').fill('');
  await dialog.getByRole('button',{name:'שמור הכרעה ידנית'}).click();
  await expect(dialog.getByText('הכרעת השיוך נשמרה עם ראיות וביקורת')).toBeVisible({timeout:20000});
  await expect(dialog.getByText('משתתף במסגרת האברכים')).toBeVisible();
  await expect(dialog.getByText('תקף כעת')).toBeVisible();
  await expect(dialog.getByText('יומן החלטות',{exact:false})).toBeVisible();
  await page.reload();
  dialog=await openPerson(page,'תורם בדיקה');
  await dialog.getByRole('button',{name:'השתתפות וזיקות'}).click();
  await expect(dialog.getByText('SYNTHETIC_FIXTURE_VERIFIED',{exact:false})).toBeVisible();
  await expect(dialog.getByText('תקף כעת')).toBeVisible();
});
