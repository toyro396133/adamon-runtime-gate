# Security implementation candidate — NOT execution authority

The code implements real Ed25519 signatures with the accepted permit/proof domain separators, canonical encoding, one-use expiring channel challenges, an authoritative SQLite FULL/WAL transactional permit ledger with unique subject-attempt and consume CAS, signed revocation, bounded leases and append-only hash-chain verification. `payload_validator` must be supplied from the separately pinned full v4 schema; synthetic tests intentionally use an independent tiny synthetic schema, not private scientific identities. Every identity/context property in the verified permit must match a trusted binding at consume. Do not pass request JSON as that trusted binding.

`process.py` checks a pre-existing supervisor-owned pidfd record against live UID, executable digest, birth time, cgroup and accepted-stream SO_PEERCRED. It does not create a trusted record from an arbitrary PID. `bridge.py` receives the Runner's private inherited socket framing and SCM_RIGHTS; malformed/unknown role/operation/fields/FD counts/digests fail closed. These are transport and authorization primitives, not a standalone enrollment service.

**Runtime BLOCKED**: full integration and validation of the native clone3(CLONE_PIDFD)/immutable execveat spawning with distinct UIDs/namespaces/cgroup/seccomp/LSM; first key issuance and sealed-memfd transfer; full supervisor assignment/API correlation and Worker lifecycle; end-to-end provisioned CA identity issuance and role-channel integration; management issuer/ACID-ledger remote availability and rollback protection; full cgroup cleanup. No fallback based on public job ID, UID or caller PID exists. `spawn_verified_launcher` raises BLOCKED unconditionally. The standard Python ssl stack does not expose the required exporter and commonly rejects unknown critical certificate extensions; `channel.py` cannot be considered a working full mTLS bootstrap service until a reviewed backend handles both. Signing and ledger tests do not prove OS isolation, VM confinement, cancellation or complete security.

`Ledger` has no research launch function. An eventual supervisor must serialize process rechecks, consume, local durable journal acknowledgement and local VM start. Crash after consume requires a new owner permit. Lease expiry/revocation requires lifecycle kill, currently not wired to the blocked supervisor. A caller cannot convert a passed primitive test into execution permission.

Run only synthetic tests:

```
python -m unittest discover -s infrastructure/t3/security/tests -v
```

All tests operate on generated synthetic keys/identities and disposable databases, never Round-2 evidence or T3 lives. No workflow dispatch or infrastructure allocation occurs. This implementation remains fail-closed and requires independent implementation review and actual hosted preflight before any source freeze or execution permit.

## Additional concrete candidate implementations

`native_supervisor.c` now provides a compile-tested library (no executable or public enrollment CLI): clone3 creates pidfd at birth and atomically joins the held Job cgroup; separate mount/net/IPC/UTS namespaces, paused inherited sync FD, immutable/read-only/verity executable FD checks, closed descriptor allowlist using close_range, supplementary-group removal and permanent UID/GID drop, execveat, error-pipe exec acknowledgement plus live pidfd check, sealed 32-byte memfd, pidfd kill and a post-exec mutation syscall filter. That filter is explicitly an incomplete deny-list, not the required reviewed final allow-list/LSM/mount confinement. Namespace/cgroup creation and successful privileged launch remain UNVERIFIED and disconnected from research starts. CLOEXEC EOF+live pidfd still requires the supervisor's post-exec executable/inode/security-profile identity recheck before keys.

`openssl_channel.py` adds an actual pyOpenSSL TLS 1.3 backend and exporter. A real synthetic accepted Unix stream handshake with mutual certificates, pinned CA, Ed25519 client key, SPKI, private critical identity extension and matching exporters passed. Only OpenSSL's leaf error34 (unknown critical extension) may be handled, after independent direct pinned-CA signature/time/EKU/key-usage/binding/SPKI checks; another unknown critical extension fails. This is a direct issuer profile, not an arbitrary CA chain or enrollment authority. Dependencies tested in isolated virtualenv: pyOpenSSL26.4.0, cryptography50.0.2, cffi2.1.1. They are not frozen execution environment authority.

Synthetic result: 14 tests passed with the pyOpenSSL backend. Native library compiled with `gcc -Wall -Wextra -Werror -fPIC -shared`; sealed memfd readback/write rejection and zero-UID spawn rejection passed. Successful clone3/bootstrap, full restrictive profile, protected assignment correlation, key issuance, Job cancellation and VM confinement still require integration and preflight. Earlier standard-ssl backend limitations remain applicable only to `channel.py`; use no tls-unique substitution.

## Private supervisor orchestration candidate

`supervisor.py` implements a retained private-channel state machine: only the
supervisor's Listener/Worker endpoints enter it; duplicate request IDs fail;
Listener raw-assignment bytes and SHA are preserved; a birth-created Worker
must acknowledge those identical bytes before authorization. An injected,
owner-pinned closed-assignment validator is mandatory. Authenticated REST run
identity and exactly one in-progress Job must match the workflow/ref/SHA,
runner ID and integer Job identity. `fixed_step_execute` checks the literal
marker then remains unconditionally `NO_APPROVED_EXECUTION_FREEZE`.
`BootstrapCA` constructs a real Ed25519 leaf with the critical binding extension
and seals its key in a native memfd only after live ProcessRecord rechecks.
The CA/REST/assignment/native capabilities must be owner-provisioned; no public
endpoint, user PID enrollment, workflow secret or generic shell was added.

The native role API now distinguishes Listener FD198, Worker bridge FD199 and
launcher key FD200. Worker ProcessChannel uses distinct FD196/197; executable
and error/bootstrap descriptors are protected against remapping collisions.
Role-specific argv is closed. ProcessChannel descriptor ordering, privileged
spawn, initial namespace network configuration, immutable deployment mounts,
complete LSM/seccomp policy, key transfer, management availability, lifecycle
wiring and real VM integration remain runtime UNVERIFIED. This is not a claim
that a candidate role spawn can run a Job today. Do not replace that validation
with the synthetic REST/state tests.

21 synthetic tests pass in the system Python (one optional pyOpenSSL backend
suite skipped there); native C compiles with all warnings treated as errors.
The canonical permit binding test explicitly rejects boolean `True` where the
owner signed integer Job ID `1`, avoiding Python's bool/int equality trap.

## 2026-10-11 — Nonresearch hardening (post-delivery)

Supervisor now independently enforces the Listener/Worker operation allowlist, in
addition to the private bridge's validation. A synthetic regression verifies that
a Listener cannot acknowledge, authorize or execute Worker operations.

`watchdog.py` adds an inert, supervisor-injected fail-closed heartbeat policy for
Worker/launcher/process exit, assignment loss, permit revocation, timeout and
cancellation. On failure it attempts credential revocation, cgroup termination and
partial evidence preservation independently, even if another cleanup operation
raises. Six standalone synthetic unit tests were executed locally and passed.
The tested source/test Git blobs match the files on this branch.

This is **not** a connected host watchdog. No live GitHub assignment source,
privileged pidfd/cgroup driver, deployment supervisor process, runner binary or
microVM is attached. It must not satisfy IMP-002/IMP-005 or authorize T3.

## 2026-10-11 — Trusted GitHub REST identity adapter

`github_rest.py` now provides an owner-injected, fixed-route
`GitHubApi.get_run/get_jobs` adapter matching the Supervisor's closed
correlation interface. It fetches the exact GitHub Actions run attempt,
attempt-scoped jobs, and the workflow **blob SHA** from the immutable
head commit. It distinguishes the numeric REST Job ID from the
Runner's private GUID and rejects non-dispatch runs, invalid attempts,
missing/ambiguous records, unsigned caller data and unknown routes.

`OwnerAuthenticatedTransport` restricts endpoints to GitHub API fixed
routes, verifies HTTPS, disables proxy inherited from the environment,
disallows redirects so bearer credentials cannot be forwarded to another
host, bounds response bodies and forbids caller-provided URLs.
Credentials must come from an owner-controlled token provider,
**never** a workflow variable.

Seven nonresearch mock-transport unit tests passed locally, and exact
Git blob IDs of the published implementation and tests matched the locally
executed files. These tests are not authenticated GitHub Job preflight:
no live owner token, signed deployment, real-run correlation, worker pidfd
or execution freeze has been proven. The adapter is injected into a future
privileged Supervisor; no public HTTP enrollment or workflow is installed.

## חיבור Runtime נוסף — 2026-10-11

`RunnerAssignmentBinder` מקבל את מפענח המקור המוצמד, קושר את `job.check_run_id` ל־`check_run_url` מה־REST ול־Runner ID מתוך תצורת Supervisor, ורק אז מפיק Actions Job ID. GUID של orchestration, Check Run ID ו־Job ID אינם מוחלפים זה בזה. `workflow_sha` הוא commit SHA; מזהה blob נשמר בנפרד. ניסיון ההרצה נקשר ל־endpoint של attempt גם כשה־Job JSON אינו כולל שדה `run_attempt`.

`NativeProcessFactory` מחבר executable FD מוצמד, UID נפרד ו־cgroup FD ל־clone3, שחרור הילד, exec acknowledgement עם timeout ו־ProcessRecord מבוסס pidfd שנוצר בלידה. `NativeWorkerSpawner` מעביר את שני pipe FDs ואת ערוץ ה־Worker הפרטי בפועל, משאיר endpoint ב־Supervisor ומטפל בהודעות עד ביטול. `EnrolledJobWatchdog` מחבר אימות ProcessRecord, קורלציית REST וחידוש ledger; סיום מקומי מבטל lease בלי ליצור היתר חדש.

אלה חיבורי קוד ממשיים אך **אינם ראיית deployment**: clone3 עם cgroup/namespace/UID, תמונת immutable, LSM, Listener networking ו־Launcher image עדיין זקוקים ל־Preflight במארח מורשה. factory אינו מרשה argv של Firecracker ואינו תחליף ל־VMM launcher סגור. REST לא אומת מול GitHub חי כאן; מבחני JSON הם סינתטיים. `fixed_step_execute` נשאר חסום ללא סמכות ביצוע מאושרת. ה־transport משתמש ב־proxy וב־CA של הסביבה ואינו עוקף אותם.

`connect_native_supervisor(...)` מרכיב ישירות את מפענח `Runner` המוצמד, REST, הקישור Check/Job/Runner ו־Native Worker factory. אין צורך להמציא מתאם Assignment נוסף. ה־factory אינו מנפיק סמכות ביצוע.

`SessionController.open()` מבצע בפועל אימות peer לתהליך Launcher שנשמר, mTLS 1.3, SPKI והרחבת binding קריטית, challenge חד־פעמי קשור exporter/request, הוכחת Ed25519 וצריכה אטומית ב־ledger. תוצאתו היא `AUTHENTICATED_ONLY`, ללא API להפעלת מחקר. במבחן החיבור בוצעו TLS, חתימות, socket peer ו־SQLite אמיתיים; קורלציית GitHub ותצורת בעלים נשארו סינתטיות ולא הוצגו כראיית GitHub Runtime.

בדיקת cancellation נוספת הורגת שני תהליכים מקומיים אמיתיים באמצעות pidfd, מסיימת lease ב־SQLite ושומרת קובץ partial. היא **אינה** מוכיחה הריגת cgroup שלם, הפרדת UID או Job מרוחק. ספריית native נטענת מעותק memfd אטום של אותם בתים שאומתו ב־SHA256, כדי להסיר מרוץ pathname בין hash ל־dlopen. מבחני GCC ומפתחות memfd אמיתיים עברו.

מנפיק Bootstrap שולח uint32 באורך big-endian, JSON סגור עם certificate/binding/SPKI, ו־FD אחד עם מפתח 32 בתים אטום. מנגנון הנפקה מבוזר/attestation של guard ומארח GitHub מורשה עדיין דורש בדיקה. הרכבת Namespace רשת של Listener ו־Worker עדיין אינה ממומשת; namespace חדש ללא הגדרת רשת אינו proof ל־Runner מחובר.

קשירת Session עודכנה לשמות permit בסכמה הקפואה: `repository_id`, ‏`workflow_path`, ‏`workflow_sha`, ‏`ref`, ‏`commit_sha`, ‏`step_sha256`, וכן `worker_job_guid`, ‏`worker_request_id`, ‏`plan_guid`. כולם נבדקים מול Assignment מנורמל; שדה חסר נכשל סגור. מזהה repository נבדק גם מתוך REST. תשעה permits חתומים עם tuple שגוי ו־Job/assignment digest נכונים נדחו לפני TLS; אלה ראיות לוגיקה/חתימות/ledger מקומיות ולא אישור GitHub חי.

### סירוב לפני יצירת Worker — 2026-10-12

Supervisor קורא כעת את זהות REST המלאה גם אחרי פענוח Assignment ולפני
`spawn_worker`. שינוי workflow/ref/SHA או זהות מאגר נדחה לפני יצירת תהליך;
בדיקה שלילית מאמתת שה־factory כלל לא נקרא. בבדיקות החוזרות לאחר ACK ובפתיחת
Session נבדק גם check_run_id מול ה־Job הפעיל, ולא רק job_id/runner_id.
אם הבעלים הצמיד workflow_blob_sha, יש אימות של אותה טביעת blob בכל correlation.
זהו חיבור קוד שנבדק עם REST סינתטי; אין כאן ראיית הקצאת Job חיה מ־GitHub.

כשל פענוח בערוץ המוגן מפעיל כעת revoke גם כאשר אין עדיין בקשה תקינה;
בדיקת socketpair אמיתית שולחת frame באורך אפס ומוודאת סירוב ללא handler.
שורש מפתחות הבעלים ב־Ledger הוא snapshot לקריאה בלבד: שינוי המפה המקורית
לא מחליף signer לאחר ההתקנה. בדיקות REST הן סינתטיות במכוון; בדיקות תעבורה
ושמירת מפתחות מקומיות אינן ראיית הרשאות Runner/LSM או צריכה בענן.

### חיבור חתום לפריסה ול־bootstrap — מועמד תשתית

`connect_deployed_supervisor` מאמת חתימת Deployment, תשעה image descriptors
בלתי משתנים, executable נפרד לכל תהליך, UID/GID, VM assets ו־jail. הוא בודק
ש־Listener הוא התהליך המוצמד ומחבר את המפענח, REST ו־NativeWorkerSpawner.
כל birth בודק שוב פקיעת סמכות, בתים ותצורת factory. חסר ב־KVM/assets חוסם
את הבנאי, ואינו מוחלף ב־boolean.

`prepare_deployed_launcher_credential` דורש BirthOrder מסוג GUARDED ו־ProcessRecord
זהה. הוא יוצר sealed key בלבד, כולל SPKI אמיתי בטביעת התעודה, ואז מציג לבעלים
binding לחתימת permit. `deliver()` בודק permit במצב ISSUED עם כל tuple
ה־Assignment, source/fixture, role/subject, SPKI ו־deployment, לפני SCM_RIGHTS.
הקריאה אינה consume: ה־challenge של mTLS והצריכה האטומית נשארים ב־Session.
ה־Session מאמת שוב את הפריסה. helper ה־bootstrap הוותיק נשאר לבדיקת wire
ללא מחקר; הוא אינו נתיב פריסה מאושר.

`deployment_sha256` הוא שדה קשירה **מועמד חדש לתשתית**, ולא שינוי בסכמת
המחקר הקפואה. validator קפוא הדוחה אותו ממשיך לדחות. השימוש למחקר נשאר
BLOCKED עד ביקורת ואישור נפרדים לסכמת הפריסה/permit. בדיקות הקוד המקומיות
מוכיחות סירוב לחתימה חסרה, FD משתנה, birth ללא guard ו־permit שגוי/שנצרך;
אין ראיה לפריסה privileged, להקצאת GitHub חיה או ל־bootstrap הזה עם KVM.
