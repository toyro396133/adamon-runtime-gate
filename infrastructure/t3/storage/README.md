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
