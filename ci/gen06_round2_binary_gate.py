"""Public-safe wrapper for a private ADAMON Gen0.6 binary evidence audit.

No private content, identifiers, digests, tracebacks, or logs are published.
This wrapper invokes a pinned audit tool checked out from private cognitive-zero.
The private audit tool performs its own strict checks and saves a private verdict
which is read only locally and removed at the end of the runner job.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    source = pathlib.Path(sys.argv[1]).resolve()
    tool = source / ".github/audit/gen06_round2_binary_verify.py"
    result_file = source / ".github/audit/round2_binary_audit_result.json"
    if not tool.is_file() or result_file.exists():
        raise SystemExit("ENVIRONMENT: expected audit tool absent or stale result present")
    with tempfile.TemporaryDirectory(prefix="adamon-r2-private-run-",
                                     dir=os.environ.get("RUNNER_TEMP")) as area:
        private_log = pathlib.Path(area) / "private-run.log"
        with private_log.open("wb") as log:
            process = subprocess.run(
                [sys.executable, str(tool)],
                cwd=source,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            )
        status = "INCOMPLETE"
        passed = {}
        if result_file.is_file():
            try:
                result = json.loads(result_file.read_text(encoding="utf-8"))
                checks = result.get("checks") or {}
                if process.returncode == 0 and result.get("status") == "PASS_INDEPENDENT_BINARY_AND_SEMANTIC_EVIDENCE_CHECKS":
                    source_check = checks["frozen_sources"]
                    archives = checks["archives"]
                    sqlite = checks["sqlite_objects"]
                    integrity = checks["sqlite_integrity"]
                    d10 = checks["ll3_d10"]
                    d67 = checks["d6_d7"]
                    controls = checks["restart_revision"]
                    if (
                        source_check["files"] == 166 and source_check["all_sha256_match"] is True
                        and len(archives) == 3
                        and sum(x["member_count"] for x in archives.values()) == 188
                        and all(len(x["boundaries"]) == 12 for x in archives.values())
                        and archives["T2_partial"]["complete_captures"] == 8
                        and sqlite["references"] == 30 and sqlite["unique_objects"] == 23
                        and sqlite["sha256_and_sizes_all_match"] is True
                        and all(integrity[k] == 23 for k in ("integrity", "foreign_keys", "global_verifier", "canonical_digests"))
                        and all(d10[tier]["status"] == "PASS_INDEPENDENT_SOURCE_RECONSTRUCTION" for tier in ("T1", "T2"))
                        and all(d67[tier]["D6"] == d67[tier]["D7"] == "PASS" for tier in ("T1", "T2"))
                        and all(controls[tier]["restart_clean"] == controls[tier]["restart_pending"] == controls[tier]["typed_revision"] == "PASS" for tier in ("T1", "T2"))
                    ):
                        status = "BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING"
                        passed = {
                            "frozen_python_sources": 166, "archives": 3,
                            "archive_members": 188, "boundary_captures": 36,
                            "original_sqlite_references": 30, "original_sqlite_objects": 23,
                            "ll3_tiers": 2, "d6_d7_tiers": 2, "restart_revision_tiers": 2,
                        }
            except (KeyError, TypeError, ValueError, OSError):
                pass
        public = {
            "status": status,
            "run_completed": process.returncode == 0,
            "checks_completed": passed,
            "independent_review_acceptance": "NOT_SELF_DECLARED",
            "gen06_verified": False,
            "t3_authorized": False,
            "note": "Public summary excludes all private repository content and raw execution details.",
        }
        output = pathlib.Path(os.environ.get("RUNNER_TEMP", area)) / "adamon-r2-public-sanitized.json"
        output.write_text(json.dumps(public, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write("## ADAMON Gen0.6 independent binary evidence gate\n\n")
                stream.write("- Audit outcome: \`" + status + "\`\n")
                stream.write("- Private source and evidence: never uploaded\n")
                stream.write("- Independent reviewer acceptance: pending\n")
                stream.write("- Gen0.6 verified: no; T3 authorized: no\n")
                if passed:
                    for key, number in sorted(passed.items()):
                        stream.write("- " + key.replace("_", " ") + ": " + str(number) + "\n")
        print("ADAMON_G06_BINARY_GATE:", status, flush=True)
        if status != "BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING":
            print("Audit did not complete. Raw private logs were suppressed; investigate only through a private trusted review channel.", flush=True)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
