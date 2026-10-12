# Owner deployment entry and reproducible build input

`OwnerDeploymentService` is an owner-only Python entry API. It validates the signed
Deployment and all typed/native prerequisites before native Listener birth, then
joins the existing REST identity / retained bridge / Worker factory. Credentials
and evidence brokers are private owner objects. No RPC command, URL, path or PID
is accepted. Cancellation tears down every retained native role and cgroup and
preserves PARTIAL; an independent watchdog remains mandatory.

`DeferredLocalGuest` connects the pinned local Firecracker UDS only after
`InstanceStart`, then uses the production GuestClient and signed completion.

`build_bundle.py` makes deterministic, exact-source-pinned build inputs:

```sh
python -m infrastructure.t3.deployment.build_bundle --expected-manifest /owner/read-only/source-manifest.json --output /owner/build-input.zip
```

The expected manifest must be produced from the reviewed commit in an independent
owner checkout with `source_manifest()` and canonical JSON. Output is exclusively
created; its receipt includes exact-byte SHA256 and size. It contains public
infrastructure source only, never private scientific fixtures or evidence.

**This source ZIP is not a deployable executable image.** It does not claim to
have built Python/cryptography/OpenSSL, Runner, Firecracker, kernel or rootfs. Those
actual bytes and toolchain dependencies must be supplied, pinned and built by the
owner; Deployment.verify_images verifies immutable descriptor bytes before birth.
There is no unpinned download or fallback. Full rootfs/init image assembly remains
a concrete deployment implementation gap until the pinned build environment and
boot contract are supplied. KVM/live namespace/cgroup/egress proof is not produced
by this source bundle. No provisioning, workflow dispatch or research permission
is granted.

The concrete fixed nonresearch image path is additive:

- `nonresearch_images.guest_init()` is the rootfs `/sbin/init` entry. It listens
  on AF_VSOCK port 52, generates an ephemeral completion key, validates an
  owner-signed **purpose-scoped delegation**, then the production signed
  injection, executes only compiled SQLite canary code, exports exact signed
  artifact bytes and invokes fixed Linux poweroff. No scientific adapter exists.
- `launcher_entry.run_owner_nonresearch_launcher(...)` runs inside an
  owner-created native Launcher jail. It performs VMM birth, irreversible guard,
  reads a sealed **delegated** injection key, drives Firecracker through fixed
  local API, defers Guest connection until boot and passes original authenticated
  bytes to the private evidence broker. The owner's root signing key is never
  supplied to Launcher. Delegation binds exact job/run/attempt, Workflow,
  assignment, permit, Launcher SPKI, role/subject, source/fixture and expiry.
- `cgroups.OwnerCgroupScope.create(owner_parent_fd, authenticated_job_id)`
  creates fixed Job/control cgroup-v2 directories only within an owner-approved
  parent FD. Worker/Launcher belong to Job; Listener/watchdog/storage are outside
  Job in control scope. It fails closed on non-root, wrong filesystem, absent
  controllers or duplicate directories. It does not grant permissions or obtain
  an approved host. Namespaces/jail/mount/UID creation use existing native
  `p4_spawn_launcher_vm_paused` / `p4_provision_jail`; no alternate clone backend.
- `rootfs_build.py` assembles source-pinned nonresearch Guest rootfs with pinned
  owner base tree, fixed init and public owner key, then executes a pinned sealed
  `mke2fs` binary descriptor offline:

```sh
python -m infrastructure.t3.deployment.rootfs_build --base /owner/base --base-manifest /owner/base-manifest.json --source-manifest /owner/source-manifest.json --owner-public-key /owner/public-key.bin --staging /owner/nonresearch-stage --output /owner/nonresearch-rootfs.ext4 --mke2fs /owner/tools/mke2fs --mke2fs-sha256 OWNER_REVIEWED_TOOL_SHA256
```

The command requires independently supplied exact owner tool SHA and all base
file SHA256/modes, never fabricated hashes. Base includes real pinned Python
3.12, cryptography/OpenSSL and loader libraries; test base is explicitly synthetic
and is never executed. Build tool dynamic loader/library dependencies still need
an immutable owner build environment, and two-build byte reproducibility remains
unverified. Launcher executable ELF/static-packaging and full boot-image
compatibility remain unverified; the entry API is concrete Python code, not a
claim that a static binary was produced. No live boot, VM teardown, UID/namespace
or cgroup creation test has run in the restricted workspace. Actual local tests
cover process pidfds, cancellation races, socket guest handshakes, delegation,
original SQLite export, source bundle determinism and rootfs source assembly.

A future owner executable packaging command must preserve these exact entry
APIs and immutable pinned dependencies. It must not package owner's root keys,
science adapters, arbitrary command dispatch or a fallback interpreter. Current
`OwnerDeploymentService` remains owner API, not a self-contained fully packaged
service image: publishing a source bundle does not close that implementation gap.
