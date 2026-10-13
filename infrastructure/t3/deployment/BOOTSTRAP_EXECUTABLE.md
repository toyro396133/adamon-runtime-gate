# Descriptor-bound executable bootstrap

`executable_build.build_executable()` builds two distinct Linux x86-64 ELF
images from an embedded CPython C entry: OWNER and LAUNCHER. It does not relabel
a ZIP, script or Python module as an executable. Arguments and environment are
not configuration. CPython uses isolated initialization and fixed immutable
`/runtime/python` and `/source` import trees. The launcher matches native
`execveat` argv (exactly one argument) and bootstrap FD 200. OWNER starts with
FD 201, outside Job cgroup; no interactive shell is used.

The image contains the public trust anchor at read-only `/owner-public-key`.
The inherited AF_UNIX SOCK_SEQPACKET channel accepts one canonical signed
bootstrap envelope and the exact SCM_RIGHTS descriptor set. The peer must have
UID 0. The private key never enters the bootstrap packet. The signature covers
all descriptor names, role, deployment, deadline and configuration. Expiry is
at most 300 seconds. Every descriptor is CLOEXEC after receipt and closed on
failure/termination. Launcher additionally inherits retained Worker pidfd 203
from the native implementation. Unknown fields, role, FD counts and packet
truncation fail closed.

`assemble_owner` creates the actual NativeProcessFactory and
OwnerDeploymentService with typed jail, VM, volume and listener-network
capabilities; `assemble_launcher` invokes the actual joined nonresearch
launcher. BrokerCapabilities and OwnerBrokerServer implement fixed private
operations for token retrieval, revocation, original-byte sealing and partial
preservation. The server is tied to a retained live ProcessRecord. Only the
compiled nonresearch canary can request live authorization. There is no shell,
module selection, path or arbitrary command operation and no scientific
permit or global PASS operation.

The owner must supply real CPython 3.12 development headers/library, complete
compiler/helper/header closure, runtime/stdlib/cryptography closure and loader
pins. The build rejects incomplete/unlisted/symlinked toolchains and mutable
compiler filesystems. Packaging records actual ELF/source/toolchain SHA256 and
build output. An ELF loader must be pinned in the runtime manifest and its
actual filesystem must be read-only before obtaining a sealed executable FD.
All loader dependencies and Python native extension dependencies must be
independently checked in owner preflight. The owner prepares this runtime tree
inside the launcher jail before native entry; it cannot be supplied by a Job.

Local verification executes an actual gcc-built static smoke ELF through its
sealed descriptor and checks exit 23. This is explicitly neither the embedded
CPython production image nor KVM. Production build remains blocked here by
missing CPython development/toolchain closure and a read-only owner runtime.
Privileged image mounting, network/cgroup creation, full Runner build and
Actions/KVM boot are independent live preflight requirements, not proven by
these local tests. No workflow, infrastructure or research experiment is
installed or invoked.

OWNER bootstrap additionally carries a signed `network` member containing
`policy`, `binding_sha256`, and `holder_pid`, plus `network_holder_pidfd` and
`network_control` descriptors. The binding is exactly SHA256 of canonical
`approved_identity`, and the signed NetworkPolicy must match it. Adoption checks
UID 0, AF_UNIX SEQPACKET peer, retained pidfd's kernel `Pid`, root holder UID,
network namespace identity and policy before use. It duplicates descriptors so
that cleanup ownership is explicit. The complete OwnerNetworkScope is passed
to OwnerDeploymentService, which starts its NamespaceConnectBridge and closes
both bridge and holder on cancellation. Passing a bare namespace FD is no
longer sufficient for standalone OWNER entry. Failed adoption closes only its
duplicates and never kills an unvalidated process. A later assembly failure
closes the validated scope. The sender must close transferred descriptor copies
after successful transfer; the service owns its adopted copies.

The adoption positive unit test uses an explicitly labelled kernel-validation
double with real sockets and pidfd; it does not prove privileged netns birth.
The actual non-owner/host-self adoption rejection test checks that caller FDs
remain open and that no host-process termination occurs.
