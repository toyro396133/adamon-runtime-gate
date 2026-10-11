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
