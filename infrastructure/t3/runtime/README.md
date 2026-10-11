# Local Job microVM lifecycle

This component implements closed Firecracker Unix-HTTP serialization and a
one-shot lifecycle behind the supervisor's serialized creation lock. It accepts
no shell, command, caller path or remote compute URL. Firecracker/kernel/role
root digests and the exact role/subject registry are supervisor-injected from
private reviewed authority. Research public entry always raises
`NO_APPROVED_EXECUTION_FREEZE`.

Native deployment must supply immutable jailed `/kernel`, `/rootfs` and
encrypted `/evidence` mounts, separate supervisor/Worker/launcher/VMM UIDs,
pidfds and the actual GitHub Job cgroup. The VMM is created by the privileged
native supervisor, not by this Python process or a workflow-provided command.
Only its already connected local AF_UNIX API descriptor is injected. The fixed
vsock listener is inside the same jail; no remote address exists.

`guest.py` implements framed local initialization and signed completion: exact
Job/run/attempt, role/subject, workflow/assignment, launcher SPKI, consumed permit
and source/fixture digests are compared before dispatch. Adapter functions are
injected from an immutable private role image; no research code ships publicly.
An Ed25519 completion must authenticate the exact request and immutable artifact
inventory. Lifecycle cannot seal success on exit status alone. Completion is
not an overall PASS receipt; only the separate Aggregation contract signs PASS.

AUDIT originals are a read-only Firecracker drive and host mount; derived
scratch must be separate RAM-backed guest storage. Complete evidence sealing
is storage-broker-only. Cancellation, expired authority, failed guest, timeout
or any preparation exception revoke credentials, kill the entire Job cgroup
and preserve private partial bytes without deleting history. A hard supervisor
death additionally requires the independent host cgroup/pidfd watcher.

On success `stop_subject_scope` kills only the VM/role subgroup so the Worker
can report fixed-step completion. Supervisor kills the remaining full Job scope
after its completion acknowledgement. Native descriptor control implements
pidfd readiness/waitid, kernel cgroup.kill and PID-reuse-safe signals; tests mock
signals and cgroup files and are explicitly not kernel-isolation proof.

`owner_runtime_preflight_verified` is a trusted capability prerequisite, not
proof supplied by the workflow. No concrete deployment satisfying these
prerequisites exists in this package. Isolation/persistence/KVM/guest execution,
key delivery, watchers and cancellation after machine loss remain untested
runtime blockers. Synthetic tests check configuration and fail-closed ordering
only. They start no VM and are not T3 or a security isolation proof.

Run synthetic tests: `python -m unittest discover -s infrastructure/t3/runtime/tests -v`.

## 2026-10-11 — Guest completion inventory hardening

The signed Guest completion reader now rejects artifact IDs that are not 64
lowercase SHA256 hex characters, duplicate object IDs, invalid/null/latest
VersionIds, zero-sized or bool-sized artifacts, out-of-range sizes and malformed
signature encodings. Added negative test fixtures exercising syntactically signed
but invalid references. The published repository contains tests; the full public
test suite was not run in this session, and real S3 readback remains UNVERIFIED.
No research entry point was enabled.

## המשך Runtime — 2026-10-11

`injection.py` קושר חתימת Ed25519 למזהי Job/Assignment/Permit, למקור ול־fixture לפי SHA256, למפתח החתימה המדויק של Guest, לתפוגה ולצריכה חד־פעמית. מקור ו־fixture מוחזרים כבתים למתאם סגור; אין חילוץ נתיבים או פקודות מקלט. `vsock.py` מממש handshake מקומי קבוע של Firecracker ל־port 52. `launcher.py` מאמת FD אטום או filesystem לקריאה בלבד, זהות jail ו־UID מופחת, ומגדיר exec קבוע ו־API מקומי המאומת ב־SO_PEERCRED. `watchdog.py` רץ בתהליך מפקח נפרד ומטפל במות supervisor, deadline וביטול באמצעות cgroup.kill ו־pidfd fallback, תוך שמירת סמן partial.

שש בדיקות `integration_tests/test_runtime_guest_process.py` מפעילות תהליך Guest אמיתי דרך AF_UNIX, handshake, הזרקה חתומה ומאומתת, קבלת completion חתומה, סירוב replay/Job/מפתח שגויים, FD אטום ו־SIGKILL אמיתי דרך pidfd. הן אינן מריצות Firecracker או מוכיחות בידוד KVM או cgroup.

**חסם חיבור מפורש:** שלב birth של VMM חייב להסתיים לפני הנפקת credential והתקנת native launcher mutation guard, שאוסר clone/exec. פונקציית native spawn אינה מתקינה guard בעצמה. LocalLauncher.prepare מממש סדר birth ואז guard ואז קבלת FD אטום בערוץ מקומי של המנפיק; אין לשלב Popen אחרי guard. ה־executable של Launcher ותהליך ה־broker המנפיק טרם הופעלו כשרשרת שלמה על KVM, ואין להציג חיבור זה כמוכח. חסרים executable/image של Launcher, Firecracker, kernel/rootfs חתומים, mounts מוצפנים, תהליך watchdog ב־UID/cgroup נפרדים והקצאת GitHub Job אמיתית. אין אישור ביצוע מחקר; הכניסה המחקרית חסומה. אין שימוש בתשתית בתשלום, workflow או T3/T4.

## חיבור אנכי מקומי שאינו מחקר

`vertical.py` מוסיף `NonresearchVerticalController` עם Subject יחיד וקבוע
`NONRESEARCH_SOCKET_CANARY`. הוא דורש Assignment שכבר אומת ואושר ב־Supervisor,
מבצע התאמה חוזרת ל־REST, צורך Permit חתום אטומית, יוצר תהליך Python נקי עם
`spawn` (ללא ירושת מפתחות הבעלים דרך fork), מאמת את הילד לפי pidfd ו־SO_PEERCRED,
ומעביר מפתח השלמה דרך sealed memfd ו־SCM_RIGHTS. Guest injection והשלמה נחתמים
ונבדקים באמצעות הרכיבים הקיימים. ביטול, תקלה ב־bootstrap או אובדן זהות ה־Job
הורגים את הילד בבעלות הבקר ומשמרים קבלת PARTIAL חתומה. אין API לפקודה, מודול,
נתיב קוד או מתאם שנבחרו בידי ה־Workflow.

בדיקות `test_vertical_nonresearch.py` מחברות את שרשרת הרכיבים ותהליכים בפועל.
REST ו־Assignment הם נתונים סינתטיים המסומנים כך; הדוגמאות אינן Permit מחקרי.
הן אינן מוכיחות Runner מלא, Job GitHub חי, enroll דרך mTLS, privilege separation,
בידוד namespace/cgroup או microVM/KVM. בקרת קריסת Supervisor מפעילה Watchdog
אמיתי על pidfds של תהליכים מקומיים; הכתיבה המדמה cgroup.kill מסומנת במפורש.
החסימה `NO_APPROVED_EXECUTION_FREEZE` נשארת ללא שינוי.
