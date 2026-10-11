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
        diagnostic = {"last_completed_stage": "NONE", "next_stage": "FROZEN_SOURCE"}
        if result_file.is_file():
            try:
                result = json.loads(result_file.read_text(encoding="utf-8"))
                checks = result.get("checks") or {}
                stages = (
                    ("frozen_sources", "FROZEN_SOURCE"),
                    ("archives", "ARCHIVES"),
                    ("sqlite_objects", "SQLITE_RECONSTRUCTION"),
                    ("sqlite_integrity", "SQLITE_INTEGRITY"),
                    ("ll3_d10", "LL3_D10"),
                    ("d6_d7", "D6_D7"),
                    ("restart_revision", "RESTART_REVISION"),
                )
                for index, (key, name) in enumerate(stages):
                    if key not in checks:
                        diagnostic["next_stage"] = name
                        break
                    diagnostic["last_completed_stage"] = name
                else:
                    diagnostic["next_stage"] = "FINAL_ASSERTION"
                raw_message = str((result.get("failure") or {}).get("message") or "")
                safe_failures = (
                    ("SQLite integrity failed", "SQLITE_INTEGRITY_CHECK"),
                    ("SQLite foreign key failure", "SQLITE_FOREIGN_KEYS"),
                    ("Global Verifier failed", "GLOBAL_VERIFIER"),
                    ("Verification changed original source", "SOURCE_SHA_CHANGED"),
                )
                diagnostic["error_category"] = next((code for prefix, code in safe_failures
                                                     if raw_message.startswith(prefix)), "UNCLASSIFIED")
                import re
                allowed_verifier_codes = frozenset(("SQLITE_INTEGRITY", "FOREIGN_KEYS", "MISSING_HISTORY_PROTECTION",
                    "LAYER_SET", "LAYER_CONFIGURATION", "LAYER_DIMENSIONS", "SELF_BOUNDS", "WORKING_BOUNDS",
                    "WORLD_VERSION", "CONSOLIDATION_CURSOR", "EVENT_VERSION", "EVENT_PARENT", "PATTERN_COUNTS",
                    "OBSERVER_VERSION", "DIRECT_DEEP_UPDATE", "DEEP_PROVENANCE", "DEEP_CAP_OR_DELTA",
                    "DEEP_EVIDENCE_CUTOFF", "MISSING_CAUSAL_PATTERN", "MISSING_OR_FUTURE_CAUSAL_EVENT",
                    "INVALID_SCHEMA_OR_STATE", "SQLITE_READ_ERROR"))
                diagnostic["verifier_failure_codes"] = sorted(
                    code for code in allowed_verifier_codes
                    if ("'code': '" + code + "'") in raw_message
                )
                import re
                completed = re.findall(r"SQLITE SEMANTIC VERIFIED:\s*(\d+)\s*/23",
                                       private_log.read_text(encoding="utf-8", errors="ignore"))
                diagnostic["sqlite_object_checks_completed"] = int(completed[-1]) if completed else 0
                kind = (result.get("failure") or {}).get("type")
                if kind in ("AssertionError", "KeyError", "TypeError", "ValueError", "OSError", "ImportError", "ModuleNotFoundError", "IndexError", "OperationalError", "DatabaseError", "AttributeError"):
                    diagnostic["error_kind"] = kind
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
            "diagnostic": diagnostic if status != "BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING" else None,
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
                stream.write("- Audit outcome: " + status + "\n")
                stream.write("- Private source and evidence: never uploaded\n")
                stream.write("- Independent reviewer acceptance: pending\n")
                stream.write("- Gen0.6 verified: no; T3 authorized: no\n")
                if passed:
                    for key, number in sorted(passed.items()):
                        stream.write("- " + key.replace("_", " ") + ": " + str(number) + "\n")
        print("ADAMON_G06_BINARY_GATE:", status, flush=True)
        if status != "BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING":
            print("SANITIZED_DIAGNOSTIC:", json.dumps(diagnostic, sort_keys=True), flush=True)
        if status != "BINARY_AUDIT_EVIDENCE_PASS_REVIEWER_ACCEPTANCE_PENDING":
            print("Audit did not complete. Raw private logs were suppressed; investigate only through a private trusted review channel.", flush=True)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
