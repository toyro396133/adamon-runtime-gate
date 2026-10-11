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
