# Private evidence byte transport

This public component contains no research source, fixtures, histories or keys.
It never computes LIFE, MICRO, AUDIT or campaign gates. Inject approved clients
and in-memory signing keys from the trusted broker; runner steps receive none.

`LocalEncryptedStore` is a **synthetic-only** AES-256-GCM/Ed25519 store with
SQLite create-only constraints and independent exact-version retrieval. It is
not Object Lock, OS immutability, KMS or cloud availability evidence. Local root
can delete the database. Stored tampering is detected, not prevented by privilege.

`S3EvidenceWriter` uses a fixed owner namespace, private bucket configuration,
SSE-KMS exact ARN/context, COMPLIANCE lock >=365 days, conditional create and
conditional multipart completion, SHA256 of plaintext and exact VersionId
readback. The Ed25519 envelope binds a SHA256 of the fixed bucket/campaign/attempt namespace; same-key cross-campaign/attempt/bucket substitution fails before retrieval. ETag is never accepted as a digest. `S3EvidenceReader` needs separate
read-only IAM credentials and a pinned Ed25519 key. Caller paths, commands, URLs,
latest versions and bucket choices are absent from operation inputs. Constructors
are trusted deployment configuration, never workflow RPC input.

SDK compatibility, real IAM/KMS denial, concurrent conditional/multipart races,
Object Lock resistance and independent reviewer download remain **UNVERIFIED**
until owner-authorized remote canaries. Read-only API configuration inspection
is only a prerequisite, not proof of those capabilities. No cloud resources are
allocated, no SDK credentials fetched and no network request occurs at import.
Production deployment must use a TLS-only boto3 endpoint and approved credentials;
it must prohibit endpoint override. Client injection here enables synthetic tests
and is not a replacement for signed deployment/client authority.

A failed upload leaves original sealed volume quarantined. Multipart is never
automatically aborted, source is never deleted and partial histories never become
complete. Preserve DB/WAL/SHM/log/position bytes in a signed inventory before
upload. This component preserves the supplied bytes; SQLite shutdown/quarantine
and member inventories belong to the trusted supervisor/role adapters. The same
content address cannot be overwritten. Retention must be extended beyond final
adjudication/open findings; no deletion API or lifecycle removal is implemented.
Owner still must attest key preservation and >=1 TiB private capacity.

The `cryptography` package is required. No keys are committed or written by this
code. Separate IAM broker/reviewer credentials and signer issuance are prerequisites.

Run synthetic tests: `python -m unittest discover -s infrastructure/t3/storage/tests -v`.

חיבור הקבצים בפועל נמצא ב־`chain.py`: `InventoryProducer` חותם מלאי של תוצרים שהתקבלו דרך `put`; `SignedInventoryReader` מאמת חתימות, SHA256 של המלאי, ניסיון/סמכות, VersionId, גודל וכל בת חזרה. ממשק הקורא אינו מציע כתיבה, מחיקה, latest או נתיב חופשי. שמות קבצים פרטיים ממופים לתוויות אטומות רשומות (למשל `life_sqlite`), ואינם מתפרסמים בממשק הציבורי. בדיקות החיבור מפעילות AES-GCM, Ed25519 ו־SQLite מקומי בפועל; אין בכך הוכחת Object Lock או הרשאות AWS. ראיות חלקיות ניתנות לשימור אך נדחות בקריאה המיועדת לקבלה.

### Connected nonresearch evidence handoff

`broker.NonresearchEvidenceBroker` binds a verified owner-side completion receipt
(scope, permit and complete binding digest) to a closed two-member inventory.
It preserves the supplied original bytes without regeneration, seals them with
AES-GCM/Ed25519 locally, and appends a terminal attempt under an atomic retained
head comparison. Missing originals, stale heads and repeat terminal records fail
closed. `open_nonresearch_audit` verifies the chain and inventory and exposes
only exact signed versions. A cancelled real Guest process produces retained
PARTIAL evidence, which this complete-Audit entry point refuses.

`integration_tests/test_evidence_e2e.py` composes the existing actual local Guest
process canary with encrypted SQLite storage and a mode=ro&immutable=1 SQLite
Audit copy. The Assignment REST response remains explicitly synthetic; these
results do not prove GitHub Job allocation, KVM, ObjectLock or remote AWS.
The handoff is `NONRESEARCH_EVIDENCE_HANDOFF` and cannot sign overall PASS.

S3 reviewer construction now requires the exact `kms_key_arn`. Before retrieving
bytes it checks the pinned VersionId, size, SSE-KMS key, COMPLIANCE mode and at
least the signed retention horizon. Writer construction requires a full 365-day
horizon. S3 tests remain injected SDK contract tests, not live IAM/KMS evidence.

The complete-Audit handoff requires owner-retained chain head/count and terminal
campaign/attempt/subject/source pins **separately** from transport data. It also
verifies the encrypted completion receipt against retained permit and full Job,
role, subject, source and fixture binding digest. Recomputed unsigned transport
summaries, chain truncation/reordering/duplicates and foreign owner/job pins fail.
The local anchor is held by the broker process; durable remote anchor publication
and live storage authorization remain deployment obligations, not demonstrated.

`control_handoff.verify_control_bytes` connects a signed exact-version inventory
to all registered original control bytes for private-injected 27/2/12/8 subject
registries. It requires each closed reference and rejects missing/version-foreign
or aliased evidence. Its only scope is
`BYTE_VERIFIED_NOT_SEMANTIC_CONTROL_COMPLETION`; `can_close_gate` is always false.
It does not execute a control, invent completion or create an acceptance receipt.

## 2026-10-12 — Guest-produced nonresearch evidence

The fixed local canary Guest now produces its own in-memory SQLite bytes. Its
Ed25519 completion pins their exact digest and size; a bounded, fixed export
operation transports those bytes before cleanup. The host verifies the signed
reference, live assignment and permit lease again, then signs a version-2
NONRESEARCH receipt with the same artifact digest/size. Broker and read-only
Audit both reject substituted bytes. Version-1 COMPLETE receipts cannot qualify
this updated canary handoff. Partial originals remain preserved separately and
cannot qualify complete Audit. This changes no research RPC or frozen receipt.

Tests use a real local Guest child, pidfd cleanup and encrypted SQLite readback;
REST identity remains synthetic. Export corruption is explicitly a host-side
transport fault injection. No GitHub/KVM/S3 live claim follows from these tests.
