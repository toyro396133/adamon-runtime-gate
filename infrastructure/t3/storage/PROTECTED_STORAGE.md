# Joined protected storage implementation

This additive increment does not alter accepted evidence, attempt, inventory or
IMP-001 code. `protected.py` binds the trusted byte broker to an owner-signed
nonresearch capability and a signed channel request. The owner-retained tuple is
campaign/attempt/subject, full Job binding digest, permit, source, fixture and
storage scope. Every operation pins the Ed25519 channel SPKI, a <=1-hour lease,
exact operation arguments, and a nonce atomically consumed in a persistent local
SQLite transaction. A signed hash-linked request journal has an externally
retained head/count; truncating a signed prefix cannot pass pinned verification.
Revocation and expiry are checked again after acquiring the transaction lock.
Authorization commits before I/O. Failure consumes that request permanently;
retry uses a new request, while the existing attempt chain still refuses a second
start or terminal history. There are no RPC paths, shell, arbitrary SQL, object
latest lookups or terminal PASS operations.

`ScopedNonresearchBroker` joins this authorization to the existing producer,
AES-GCM store, signed exact inventories and immutable STARTED/terminal attempt
chain. `ScopedInventoryReadback` exposes only registered exact versions to
AUDITOR/REVIEWER. The production classes are used by the local tests, with actual
SQLite encrypted byte persistence and Ed25519 verification. Synthetic receipts
and owners in tests are declared synthetic; those tests prove application logic,
not IAM, root-admin resistance or KVM isolation. The local SQLite administrator
can bypass triggers; ciphertext/signature and externally pinned journal/inventory
checks detect resulting modification. No claim of filesystem/ObjectLock
immutability follows from these local tests. `snapshots.py` seals the exact
canonical bytes of original signed attempt entries as a pinned encrypted version,
including incomplete/partial histories. Independent readback must supply the
retained source/campaign/subject/head/count anchor; snapshot metadata cannot
select its own trusted anchor, and a partial snapshot cannot qualify completion.

## S3 data path

`ProtectedS3EvidenceWriter` extends the existing exact-version adapter. Before
any cloud operation it checks the installed SDK S3 operation models for conditional
Put/Complete, `MpuObjectSize`, exact VersionId and SHA256 COMPOSITE support; an old
SDK is rejected instead of using a fallback. SDK versions/wheels must also be
pinned by the owner build bundle; model inspection alone is not supply-chain
attestation. It performs
read-only configuration checks for every sealing operation through a separately
injected owner configuration-reader client. The producer does not need bucket
configuration privileges. Multipart plans record full size/SHA256 and each part's
number, offset, size and checksum. Every upload response is checked. Completion
is `IfNoneMatch=*` with the ordered full part list, `MpuObjectSize`, and SHA256
COMPOSITE checksum. S3 multipart SHA256 is the hash of concatenated binary part
hashes plus `-part_count`, not the original full-object hash. Full-object SHA256
is separately verified through exact VersionId readback. Missing/wrong checksum,
truncation, wrong KMS/VersionId/lock or modified bytes fail. Failed uploads and
source bytes are retained; there is no abort/delete fallback.

## Owner-reviewed policy templates

`policies.py` produces prefix-specific producer, auditor, reviewer and owner
configuration-reader identity policies, and a TLS/conditional-create bucket
policy. Producer grants only `PutObject`, exact version readback, scoped KMS
DataKey/Decrypt. Auditor/reviewer receive exact version reads and scoped KMS
Decrypt, with explicit denies for mutation/latest/listing. Explicit wrong KMS,
encryption, lock mode or shortened retention are denied. Configuration authority,
delete, retention modification and abort are excluded. Auditor/reviewer are
separate AWS roles even though their least-privilege permission documents match.

The producer allow does not require SSE headers on CompleteMultipartUpload:
completion has no such headers. The existing verified default encryption and
COMPLIANCE default retention enforce omitted header behavior; explicit foreign
headers are denied. The conditional-create bucket deny uses
`s3:ObjectCreationOperation` so it applies to PutObject/CompleteMultipartUpload
without blocking CreateMultipartUpload/UploadPart. This AWS condition behavior,
including 409/412 races, still requires PF-07 on a dedicated synthetic bucket.

KMS permits require S3 ViaService, authority/attempt custom encryption context,
and the exact object ARN prefix. S3 Bucket Keys
must be disabled for this configuration: otherwise KMS context uses the bucket
ARN instead of the object ARN. Effective IAM, key policies, grants, SCPs and
permission boundaries must be audited separately; JSON templates alone cannot
prove them. Retention is >=365 days COMPLIANCE; unsuccessful negative writes must
also remain retained if the service unexpectedly accepts them. No cleanup may
shorten retention or delete protected original versions.

The static template command does not call AWS or provision resources:

```
python -m infrastructure.t3.storage.policies \
  --config OWNER_REVIEWED_LITERAL_SCOPE.json \
  --output NEW_POLICY_CANDIDATE.json
```

Configuration has exactly `bucket`, `kms_key_arn`, `authority_sha256`, `attempt_id`
and `region`. An existing output is not overwritten. The owner provides the
literal private namespace. Do not publish actual private bucket/key identifiers
or science evidence in the public repository.

## Remaining PF-07 live acceptance

Only an independently approved owner operation may provide a dedicated synthetic
private bucket, KMS key, separate configuration/producer/auditor/reviewer clients,
Versioning, COMPLIANCE ObjectLock >=365 days and public-access blocking. The owner
consolidates this into PF-00..09; it does not authorize research. No resources,
credentials, ObjectLock creation or paid operations were performed by this
increment. Live tests must establish:

- actual conditional single/multipart competing creates retain exactly one
  original version and the loser cannot overwrite it;
- full bytes, SHA256, size, VersionId, exact KMS key, ObjectLock and retention via
  independent reviewer identity;
- wrong KMS context/prefix, latest access, write/delete/retention shortening and
  cross-role mutation denied by actual effective IAM;
- multipart outage/truncation retains source, upload identity and PARTIAL attempt;
- independent auditor can read exact signed inventory versions and journal anchor.

Dedicated storage/requests and KMS API operations can incur AWS charges. No price
estimate is claimed without owner region/service pricing. ObjectLock COMPLIANCE
retention is irreversible until expiry. CLI templates and SDK contract tests are
STATIC_VALIDATED / SYNTHETIC_INTEGRATION_TESTED; LIVE_RUNTIME_VERIFIED is pending.
