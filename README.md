# ADAMON M2.9 runtime infrastructure

This repository contains only CI infrastructure. The private source is never
committed here. Only manual `workflow_dispatch` is enabled, without inputs.
The source SHA is frozen to `cac5213fdf0d984fd8874b739f6a06c70a77fcb9`.

Create public repository `toyro396133/adamon-runtime-gate`, commit these files
to its default branch, and add repository Actions secret
`COGNITIVE_ZERO_READ_TOKEN`. Use a fine-grained token restricted to
`toyro396133/cognitive-zero` with **Contents: Read-only** (plus GitHub's
mandatory read metadata). Do not grant write, administration or Actions access
to the private repository. Never paste the token into chat, files or commands.

Then open Actions → M2.9 frozen private runtime gate → Run workflow.
Use the standard `ubuntu-latest` runner and Python 3.12; no larger runner,
database service, dependency cache or automatic trigger is configured.

Installation and tests run in the required order. The wrapper does not modify
production files or tests. The original stage runner writes its usual evidence
under private-source/docs. Before the gate, stale gate artifacts are removed
to prevent acceptance of old evidence after an interrupted run.

Public logs expose fixed stage labels, exits and a sanitized JSON summary.
Test stdout/stderr, JUnit XML, failure messages, source manifests and databases
are never uploaded. Private raw evidence is ephemeral and deleted at cleanup;
the public summary is the retained evidence. Failure details and tracebacks
cannot be diagnosed from that summary: a private execution/review channel is
required. An unresolved test failure is reported conservatively as
GATE_INFRASTRUCTURE pending private diagnosis, not asserted to be a production
defect. Installation/access failure is ENVIRONMENT.

The stage runner validates the registered EXPECTED_MISSING_CAPABILITY failures.
The wrapper additionally verifies registration against test definitions at the
frozen source, rejects fixture errors and all skip/xfail, requires completed
TIER3/TIER4 XML and exits, checks named A-001/A-002/A-003 contracts and exact
511/512/513 cases, and compares tracked source and installed package hashes.

M2.9 remains NOT VERIFIED until the workflow completes every acceptance check.
Do not implement M2.10 or independently update the private project's roadmap.
Return the run URL, frozen source SHA, counts, versions and preservation status
to the planning agent. No runtime execution is claimed by preparing these files.


## Chacham Lev lean test runner (separate from ADAMON M2.9)

Workflow: `.github/workflows/chacham-lev-lean-validation.yml`. It tests a
pinned commit of the **private** `toyro396133/chacham-lev` repository using
the existing read-only `CHACHAM_LEV_READ_TOKEN` secret. Neither source files,
raw test output nor diagnostic artifacts are published here.

To run a newer private commit after this workflow is merged, select
**Actions → Chacham Lev lean validation → Run workflow**, supply its exact
40-hex-character commit SHA and choose `smoke` (focused), `db` (isolated PostgreSQL integration only), `full` (unit,
TypeScript and isolated PostgreSQL integration), or `all`. Only changing
the workflow file itself triggers an automatic `db` verification;
application commits do not trigger public CI automatically.

All database tests use a fresh PostgreSQL 18 service inside the job, never
production or Neon. Only status, runtime, aggregate counts and anonymous failing suite IDs/categories appear in the public summary.
A failure is **not** a PASS; private diagnostics are intentionally not
available from the public Actions log. Treat the full E2E workflow separately.


### Chacham Lev public evidence hardening (October 22, 2026)

The live acceptance workflow now uses `ci/chacham-lev-public-gate.cjs` to validate structured reports. No source stdout/stderr lines are forwarded. Structural errors, absent reports, unsuccessful stage exits and clone-cleanup failures must fail the job. `ci/chacham-lev-public-gate.test.cjs` uses synthetic secret-like strings for negative leak tests. Public PostgreSQL service logging is hardened before loading private code and its published host port is loopback-only.

Database reconstruction is an explicitly bounded **pinned historical snapshot plus approved SQL upgrades**, not a replay of all historical data migrations and not an E2E acceptance test. The independent SQL migration manifest is in the private source. The workflow also executes deliberate SQL failure cases only against temporary loopback PostgreSQL clones. Do not use a green run against an older private SHA as approval for a newer commit.

The fine-grained permissions of `CHACHAM_LEV_READ_TOKEN` must be verified in the token issuer/repository settings; the Actions job's own `contents: read` scope does **not** prove the secret's scopes. The source is not published; privately retained diagnostics are deleted after the job. Keep both PRs Draft until a separate review accepts a pinned full run and the negative tests.
