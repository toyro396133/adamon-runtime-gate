"""Pinned v2.338.0 wire decoding; requires supervisor provenance and REST verification.
A parsed packet is NOT authentication. Job GUID, check-run ID and REST job ID
are distinct domains. No secret-bearing Variables/Resources leave this decoder.
"""
import hashlib
import json
import math
import re
import uuid
from infrastructure.t3.security.protocol import canonical

MARKER = "ADAMON_P4_FIXED_LAUNCH_V4"

def _pairs(items):
    result = {}
    for key, value in items:
        if key.casefold() in {k.casefold() for k in result}:
            raise ValueError("ASSIGNMENT_DUPLICATE_KEY")
        result[key] = value
    return result

def _dictionary(value):
    if not isinstance(value, dict) or set(value) != {"t", "d"} or type(value["t"]) is not int or value["t"] != 2 or not isinstance(value["d"], list):
        raise ValueError("ASSIGNMENT_CONTEXT_DICTIONARY")
    entries = []
    for entry in value["d"]:
        if not isinstance(entry, dict) or set(entry) != {"k", "v"} or type(entry["k"]) is not str:
            raise ValueError("ASSIGNMENT_CONTEXT_ENTRY")
        entries.append((entry["k"], entry["v"]))
    return _pairs(entries)

def _text(values, key):
    value = values.get(key)
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError("ASSIGNMENT_MISSING_" + key)
    return value

def _positive(value):
    if type(value) is str and re.fullmatch(r"[1-9][0-9]*", value):
        value = int(value)
    if type(value) is float and math.isfinite(value) and value.is_integer():
        value = int(value)
    if type(value) is not int or not 0 < value <= 2**53 - 1:
        raise ValueError("ASSIGNMENT_POSITIVE_SAFE_INTEGER")
    return value

def decode_assignment(raw, expected_sha256):
    if type(raw) is not str or not 0 < len(raw.encode()) <= 1024 * 1024:
        raise ValueError("ASSIGNMENT_FRAME")
    if hashlib.sha256(raw.encode()).hexdigest() != expected_sha256:
        raise ValueError("ASSIGNMENT_DIGEST")
    packet = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("ASSIGNMENT_NONFINITE")))
    if not isinstance(packet, dict):
        raise ValueError("ASSIGNMENT_OBJECT")
    # JsonUtility has pinned camelCase DataMember names; don't accept alternate spellings.
    contexts = packet.get("contextData", {})
    if not isinstance(contexts, dict):
        raise ValueError("ASSIGNMENT_CONTEXT_ROOT")
    github = _dictionary(contexts.get("github"))
    job = _dictionary(contexts.get("job"))
    steps = packet.get("steps")
    if not isinstance(steps, list) or len(steps) != 1:
        raise ValueError("ASSIGNMENT_ONE_STEP")
    step = steps[0]
    if not isinstance(step, dict):
        raise ValueError("ASSIGNMENT_STEP_OBJECT")
    try:
        step_id = str(uuid.UUID(step["id"]))
        job_guid = str(uuid.UUID(packet["jobId"]))
        plan_guid = str(uuid.UUID(packet["plan"]["planId"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("ASSIGNMENT_GUID") from exc
    if any(value == str(uuid.UUID(int=0)) for value in (step_id, job_guid, plan_guid)):
        raise ValueError("ASSIGNMENT_ZERO_GUID")
    if step.get("type") != 4 or step.get("reference") != {"type": 3} or step.get("condition") != "success()" or step.get("enabled", True) is not True:
        raise ValueError("ASSIGNMENT_FIXED_STEP")
    if step.get("background", False) is not False or any(step.get(k) is not None for k in ("environment", "continueOnError", "timeoutInMinutes", "parallelGroupId")):
        raise ValueError("ASSIGNMENT_STEP_OVERRIDE")
    inputs = step.get("inputs")
    if not isinstance(inputs, dict) or type(inputs.get("type")) is not int or inputs["type"] != 2 or set(inputs) - {"type", "map", "file", "line", "col"}:
        raise ValueError("ASSIGNMENT_INPUTS")
    entries = inputs.get("map")
    def literal(value):
        if type(value) is str:
            return value
        if isinstance(value, dict) and type(value.get("type")) is int and value.get("type") == 0 and set(value) <= {"type", "lit", "file", "line", "col"} and type(value.get("lit")) is str:
            return value["lit"]
        raise ValueError("ASSIGNMENT_LITERAL")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict) or set(entries[0]) != {"key", "value"} or literal(entries[0]["key"]) != "script" or literal(entries[0]["value"]) != MARKER:
        raise ValueError("ASSIGNMENT_MARKER")
    if any(packet.get(k) is not None for k in ("jobContainer", "jobServiceContainers", "debuggerTunnel", "snapshot")) or packet.get("enableDebugger", False) is not False or any(packet.get(k) for k in ("environmentVariables", "defaults", "jobOutputs", "actionsEnvironment")):
        raise ValueError("ASSIGNMENT_JOB_OVERRIDE")
    result = {
        "repository_id": _positive(github.get("repository_id")),
        "step_sha256": hashlib.sha256(canonical(step)).hexdigest(),
        "run_id": _positive(github.get("run_id")),
        "run_attempt": _positive(github.get("run_attempt")),
        "check_run_id": _positive(job.get("check_run_id")),
        "workflow_ref": _text(job, "workflow_ref"),
        "workflow_sha": _text(job, "workflow_sha"),
        "ref": _text(github, "ref"),
        "head_sha": _text(github, "sha"),
        "repository": _text(github, "repository"),
        "step_id": step_id, "marker": MARKER, "job_guid": job_guid, "plan_guid": plan_guid,
        "request_id": _positive(packet.get("requestId")),
        "assignment_sha256": expected_sha256,
    }
    for field in ("workflow_sha", "head_sha"):
        if not re.fullmatch(r"[0-9a-f]{40}", result[field]):
            raise ValueError("ASSIGNMENT_SHA")
    for field in ("workflow_ref", "workflow_sha"):
        if field in github and github[field] != result[field]:
            raise ValueError("ASSIGNMENT_CONTEXT_CONFLICT")
    return result
