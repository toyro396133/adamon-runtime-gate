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
