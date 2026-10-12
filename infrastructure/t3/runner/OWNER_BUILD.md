# Full Owner Runner build execution

`python -m infrastructure.t3.runner.owner_build --bundle /owner/build-bundle.json --checkout /owner/runner --sdk /owner/dotnet/dotnet --feed /owner/locked-feed --output /owner/new-build-evidence`

This command actually restores, publishes the pinned Runner solution and runs its upstream tests. It must run only on a separately owner-authorized build host. It does not start Runner.Listener, register a runner, dispatch Actions or perform research. Bundle creation and dependency discovery remain in `build_bundle.py`.

The executor rederives and compares the complete bundle before each fixed command, including source graph, pinned SDK host, patch, overlay, all lockfiles and package content. Only diagnostic free space is excluded from equality. A fresh checkout without project.assets.json, old TRX or `_layout` is required. At least 16GiB free space is required; this is a conservative build execution floor, not the T3 host capacity policy.

The environment is an allowlist: no ambient HOME, NuGet caches, MSBuild paths, executable PATH additions or proxy/plugin variables. RestoreSources is the single verified feed from the authority bundle; fresh HOME and package caches isolate user configuration. The emitted closed NuGet configuration is retained as evidence. Original phase argv, exit codes and byte-exact stdout/stderr are recorded. Timeouts kill the entire newly created process group. Failure stops subsequent phases and retains partial-receipt.json and logs. No cleanup deletes partial evidence.

The successful publication outputs are read from the pinned upstream dir.proj destination `_layout/bin`, not transport harness or an arbitrary synthetic DLL. Original TRX and Listener/Worker bytes are copied into the fresh evidence directory and checked by verify_build_receipt. Its output is pending independent review, never independent acceptance or execution authority.

The local tests exercise actual short-lived OS children, original failure logs and timeout behavior with an explicitly test-only authority adapter. They do not establish a complete Runner build. No full restore is attempted in this exhausted workspace. Missing locks/original nupkg bytes remain reported by bundle validation; 16GiB free space does not replace the original missing-material prerequisites.

The owner must additionally isolate the checkout, SDK and feed against concurrent privileged mutation during build, deny outbound package network access and archive the bundle, package closure, logs, TRX, published binaries and receipt for independent review. Source validation before each phase detects modifications but is not an OS-level read-only mount proof.
