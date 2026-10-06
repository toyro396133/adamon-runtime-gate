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
