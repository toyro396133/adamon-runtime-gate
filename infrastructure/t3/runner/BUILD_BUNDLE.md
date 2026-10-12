# Owner-only full Runner build bundle

This is build preparation, not a GitHub Job dispatcher, experimental Workflow,
execution permit or PF-01 acceptance. It does not run a research subject.

Actual upstream is `actions/runner@197ca027b90de199464dee3bb9ff198a1db60967`
(`v2.338.0`). SDK is `8.0.425`. `create()` verifies existing patched source bytes,
all nine upstream project definitions, solution/dir.proj, SDK host SHA256 and SDK
reported version. The recorded upstream SDK archive SHA512 remains a bootstrap
pin; it is not a fresh verification of all installed SDK files. Owner must unpack
that verified original archive on a clean build host. No floating SDK fallback.

The local checkout has no verified transitive closure and insufficient storage:
prior restore failed ENOSPC, and five production project assets are absent.
A local manifest therefore says `BLOCKED_UNFROZEN_TRANSITIVE_CONTENT`, never
`RUNNER_FULL_BUILD_VERIFIED`. No repeated restore is performed here.

## Exact owner procedure on separately authorized, adequate build host

Owner supplies clean pinned checkout, patched with `apply_patch.py`, an SDK
unpacked from the pinned archive, trusted NuGet acquisition endpoint, fresh
package-cache/feed/receipt directories and sufficient storage. Administrative
paths are owner inputs, never Workflow inputs. Authentication, proxy and CA
trust follow owner policy; credentials are not in the bundle.

From the public implementation checkout, inspect without network:

```sh
python -m infrastructure.t3.runner.build_bundle --checkout "$RUNNER_CHECKOUT" --sdk "$PINNED_DOTNET" > "$RECEIPTS/prerequisites.json"
```

Owner explicitly authorizes **dependency acquisition only**. Generate original
NuGet lockfiles on the clean patched checkout; this first discovery is not a
content-frozen restore and cannot produce an accepted build receipt:

```sh
"$PINNED_DOTNET" restore "$RUNNER_CHECKOUT/src/Test/Test.csproj" --use-lock-file --packages "$PACKAGE_CACHE" --source https://api.nuget.org/v3/index.json -p:PackageRuntime=linux-x64
```

Repeat that acquisition command for `src/Runner.PluginHost/Runner.PluginHost.csproj` (the sole production project absent from Test.csproj's transitive project graph). Save all logs, exit codes and locks. Review the complete resolved closure before
approving it. Copy original nupkg bytes from the owner package cache into a fresh
local feed with `export_feed(checkout, package_cache, output)`; that function
verifies **every** resolved package against the original lockfile SHA512
`contentHash` and records SHA256/size. It downloads nothing, rejects floating
resolved versions, missing/incorrect hashes, missing projects/lockfiles/packages,
symlink packages and existing feed output. Original package/cache bytes are
never changed. Windows Service is not part of the Linux build closure; its
upstream definition is still hashed. Linux solution includes eight projects.

```sh
python -m infrastructure.t3.runner.build_bundle --export-feed --checkout "$RUNNER_CHECKOUT" --package-cache "$PACKAGE_CACHE" --output "$PINNED_FEED" > "$RECEIPTS/dependency-closure.json"
python -m infrastructure.t3.runner.build_bundle --checkout "$RUNNER_CHECKOUT" --sdk "$PINNED_DOTNET" --feed "$PINNED_FEED" > "$RECEIPTS/content-pinned-bundle.json"
```

Only after owner approval, execute the four exact argv arrays emitted in that
bundle from the pinned upstream checkout. They select upstream dir.proj's full
Linux build/publish, original Test.csproj and **locked restore with only the
verified local feed**. Do not add fallback feeds or replace package bytes. The
build entry also generates upstream BuildConstants; retain generated file,
logs and all output hashes. Build twice on two clean directories with the same
closure; compare outputs, recording differences instead of claiming byte
reproducibility if differences exist. This is external work still required.

## Receipt contract

`verify_build_receipt(bundle, receipt, evidence_root)` accepts exactly:

- `version=1`;
- `bundle_sha256`: SHA256 of sorted compact JSON of the complete approved bundle;
- `phases`: exactly restore_test/restore_pluginhost/build/tests, each with exact bundle argv, integer
  exit_code zero and nonempty original log reference;
- `outputs`: exactly Runner.Listener.dll and Runner.Worker.dll references;
- `trx`: original TRX reference with total >0 and executed=passed=total.

References are exactly `{relative, sha256, size_bytes}`. Paths remain inside the
owner evidence root, links are rejected, and bytes must match SHA256 and size.
Missing outputs, failed commands, skipped/failing tests, mutated logs, unfrozen
closure or another bundle fail closed. Validation returns only
`OWNER_BUILD_OUTPUTS_VALIDATED_PENDING_INDEPENDENT_REVIEW`, never permission to
execute research or independent acceptance. No synthetic test receipt in this
repository is evidence of an actual full Runner build.

Cleanup: retain immutable original acquisition/build/test logs, nupkg closure,
lockfiles, outputs, TRX and bundle for read-only review. Owner may remove only
new disposable build directories after preservation; never delete historical
research evidence. No cloud resources, paid storage, live Actions dispatch or
new secrets are provisioned by these helpers.

Owner receipt readback command:

```sh
python -m infrastructure.t3.runner.build_bundle --verify-receipt "$RECEIPTS/owner-build-receipt.json" --bundle "$RECEIPTS/content-pinned-bundle.json" --evidence-root "$RECEIPTS"
```
