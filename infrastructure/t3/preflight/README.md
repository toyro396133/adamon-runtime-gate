# Nonresearch preflight preparation

`python -m infrastructure.t3.preflight.check --probe` performs read-only local
capability/capacity observations. It always returns exit 2/PREFLIGHT_INCOMPLETE:
API presence, host memory and CPU observations are not security verification.
No secrets, environment variables, hostnames, paths or private source are printed.
Do not publish host capacity observations without owner review.

The workflow template deliberately uses invalid unapproved revision placeholders
and lives outside `.github/workflows`. It cannot dispatch research and must not
be installed as-is. Owner approval, exact action SHA pins and dependency hash lock
are required before a separate synthetic Actions workflow may be installed.

Remaining gated real canaries: adapted Runner build/registration legacy+broker,
privileged UID/pidfd/clone3/execveat, microVM/cgroup cancellation, non-exec profile,
mTLS peer/channel/owner permit race/revocation, encrypted S3/KMS COMPLIANCE lock,
conditional multipart races, reviewer exact bytes, leak-canary and full capacity.
Run them only after resources/access are separately authorized. Signed owner
capacity/storage attestation, independent implementation acceptance and future
prospective execution freeze plus an explicit research permit are mandatory.
This CLI, tests and template contain no research adapter entry point or T5 material.

## Closed PF-00..09 offline entrypoint

`python -m infrastructure.t3.preflight.sequence --policy OWNER_INSTALLED_POLICY.json --receipts SIGNED_GATE_RECEIPTS.json --artifacts PROTECTED_PROOF_DIRECTORY --observe-host`

This command does not provision, dispatch, register a runner, create secrets or
run a scientific adapter. `--observe-host` only adds the existing read-only
observation; CPU/API availability cannot close a live-proof gate. With no
receipts all ten gates are BLOCKED (exit 2). Exit 0 means only that the externally
signed proof package and its local artifact bytes verified, never execution
permission, an execution freeze, or independent acceptance by this program.

The policy is a **trusted input installed by the owner/reviewer**, never a
workflow-supplied trust anchor. Version 1 has precisely `version`, `context`,
`keys`, `maximum_receipt_age_seconds`, `approved_job`. `context` has exact
`campaign_id`, `private_commit`, `public_commit`, `authority_sha256`. Keys map
signer identities to precisely `role` and Ed25519 `public_key_hex`; owner and
reviewer keys must be different. `approved_job` is either null (live proof
receipts cannot verify) or the exact Actions repository/workflow ref/SHA,
run ID/attempt/job ID tuple. Policy SHA256 is computed over canonical ASCII
JSON and included in every signed receipt context. Arbitrary CLI policy files
do not establish owner identity: deployment must protect their provenance and
bytes outside any untrusted Job workspace.

A gate receipt is `{payload, signature_hex}`. Payload has precisely `version`,
`gate`, `kind`, `signer`, `issued_at`, `expires_at`, `context`,
`owner_authorization_sha256`, `job`, `requirements`, `artifacts`, `status`.
Signature domain is `ADAMON-PREFLIGHT-V1\n` followed by sorted compact ASCII JSON
bytes. The PF-00 hash binds all later receipts to owner authorization; PF-09
requires all preceding gates to PASS and the separate reviewer signer. Jobs
are mandatory for PF-02..08 and match the owner policy exactly. Exact closed
requirements/roles/proof kinds are the `GATES` registry in `sequence.py`, mapped
to the planner's PF-00..09 sequence without new gates.

Each artifact has `name`, `sha256`, `size`, `requirements`: names are flat,
unique, traversal-free basenames; every PASS requirement must reference at
least one hashed artifact. Bytes are read through an O_NOFOLLOW descriptor,
regular-file/inode/size/time/hash checked, never modified. Evidence content
is not parsed as proof of the runtime claim: this CLI authenticates the signer's
attestation and exact bytes. The independent reviewer must inspect protected
logs and runtime evidence; a signature cannot make a false claim true. Keep
private proof artifacts out of public Git and Actions artifacts.

PF-01 requires a complete Listener/Worker build and pinned restore/outputs;
transport harness success is insufficient. PF-02..08 require LIVE_RUNTIME
attestations, not unit/mock/local-canary substitutes. PF-07 includes exact
version readback, KMS, COMPLIANCE retention and independent reviewer bytes.
FAIL/BLOCKED/NOT_RUN remain explicit and prevent PF-09 completion. Missing
owner authorization blocks all later gates. Missing runtime resources or
owner approval require external preflight, without stopping local engineering.

Test fixtures use ephemeral keys and **synthetic claims only**; they validate
signature/schema/replay/byte rejection, not GitHub/KVM/AWS runtime. The existing
nonresearch template remains outside `.github/workflows` and unchanged.
