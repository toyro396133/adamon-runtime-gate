"""CI infrastructure only. Never emit private test output or upload raw evidence."""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

SOURCE_HEAD = 'cac5213fdf0d984fd8874b739f6a06c70a77fcb9'
SELECTOR = 'W6 and not record_merge and not transition'
MEMBERS = (
    'tests/integration/test_organization.py',
    'tests/integration/test_organization_m2.py',
    'tests/integration/test_organization_m2_canonical_values.py',
    'tests/integration/test_organization_m2_merge.py',
    'tests/integration/test_organization_m2_merge_projection.py',
)
PACKAGES = ('SQLAlchemy', 'pydantic', 'pytest')
A_CONTRACTS = {
    'A-001': {
        'test_W6_merge_authority_cannot_select_stale_source_cutoffs': 1,
        'test_W6_historical_merge_cutoff_derives_one_authoritative_source_snapshot': 1,
    },
    'A-002': {
        'test_W6_whole_retained_distinctions_respect_exact_total_budget': 6,
        'test_W6_whole_member_refs_respect_exact_total_budget': 3,
        'test_W6_whole_internal_overflow_replays_after_close_reopen': 1,
    },
    'A-003': {
        'test_W6_complete_actor_owned_whole_and_probe_comparison': 1,
        'test_W6_retained_distinction_mismatch_reports_whole_signature_blocker': 2,
    },
}


class GateStop(Exception):
    def __init__(self, category: str):
        self.category = category


def require(condition: bool, category: str = 'GATE_INFRASTRUCTURE') -> None:
    if not condition:
        raise GateStop(category)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_snapshot() -> dict:
    result = {}
    for name in PACKAGES:
        dist = metadata.distribution(name)
        files = {}
        for file in dist.files or ():
            path = Path(dist.locate_file(file))
            if path.is_file() and path.suffix != '.pyc':
                files[str(file)] = digest(path)
        require(bool(files), 'ENVIRONMENT')
        result[name] = {'version': dist.version, 'files': files}
    return result


def source_snapshot(root: Path) -> dict:
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    # Gate evidence is written under docs; all other tracked source is immutable.
    return {name: digest(root / name) for name in names if name and not name.startswith('docs/')}


def test_results(path: Path, exit_code: int, root: Path, *, ledger: bool = False) -> dict:
    require(path.is_file())
    xml = ET.parse(path).getroot()
    require(xml.tag in ('testsuite', 'testsuites'))
    cases = list(xml.iter('testcase'))
    require(bool(cases))
    require(all(int(s.attrib.get('errors', 0)) == 0 for s in xml.iter('testsuite')))
    require(all(int(s.attrib.get('skipped', 0)) == 0 for s in xml.iter('testsuite')))
    counts = {'passed': 0, 'expected_missing': 0, 'exit': exit_code}
    for case in cases:
        require(case.find('error') is None and case.find('skipped') is None)
        failure = case.find('failure')
        if failure is None:
            counts['passed'] += 1
            continue
        require(ledger)
        message = failure.attrib.get('message', '')
        require('EXPECTED_MISSING_CAPABILITY:' in message)
        classname = case.attrib.get('classname', '')
        filename = classname.replace('.', '/') + '.py'
        require(filename in MEMBERS and 'test_organization_m2' in classname)
        # Registration comes from actual test definitions at the frozen source.
        definitions = {
            item.name for item in ast.walk(ast.parse((root / filename).read_text()))
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith('test_')
        }
        require(case.attrib['name'].split('[', 1)[0] in definitions)
        counts['expected_missing'] += 1
    require(exit_code == (1 if counts['expected_missing'] else 0))
    return counts


def verify_a_contracts(path: Path) -> None:
    cases = list(ET.parse(path).getroot().iter('testcase'))
    for contracts in A_CONTRACTS.values():
        for name, minimum in contracts.items():
            matching = [c for c in cases if c.attrib.get('name', '').split('[', 1)[0] == name]
            require(len(matching) >= minimum)
            require(all(c.find('failure') is None and c.find('error') is None and c.find('skipped') is None for c in matching))
    for name in ('test_W6_whole_retained_distinctions_respect_exact_total_budget',
                 'test_W6_whole_member_refs_respect_exact_total_budget'):
        for boundary in (511, 512, 513):
            require(any(c.attrib.get('name', '').startswith(name + '[') and
                        str(boundary) in c.attrib['name'].split('[', 1)[1] for c in cases))


def execute(root: Path, raw: Path, label: str, command: list[str], junit: bool = False) -> int:
    environment = os.environ.copy()
    # No read credential is passed to installation, tests or the stage runner.
    for key in list(environment):
        if any(word in key.upper() for word in ('TOKEN', 'SECRET', 'PASSWORD')):
            environment.pop(key)
    environment['PYTEST_ADDOPTS'] = '--junitxml=' + str(raw / (label + '.xml')) if junit else ''
    environment['PYTHONPATH'] = str(root)
    with (raw / (label + '.log')).open('wb') as output:
        result = subprocess.run(command, cwd=root, env=environment, stdout=output, stderr=subprocess.STDOUT)
    (raw / (label + '.exit')).write_text(str(result.returncode) + '\n')
    # Only a fixed label and numeric exit enter public logs.
    print(f'{label}: exit={result.returncode}', flush=True)
    return result.returncode


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    raw = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'adamon-private-evidence'
    raw.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {
        'SOURCE_HEAD': SOURCE_HEAD, 'PRE_GATE': 'NOT_RUN', 'FOCUSED': 'NOT_RUN',
        'SUPPLEMENTAL': 'NOT_RUN', 'A-001': 'NOT_RUN', 'A-002': 'NOT_RUN', 'A-003': 'NOT_RUN',
        'TIER3': {'status': 'NOT_RUN', 'passed': None, 'expected_missing': None, 'exit': None},
        'TIER4': {'status': 'NOT_RUN', 'passed': None, 'expected_missing': None, 'exit': None},
        'SOURCE_PRESERVATION': 'NOT_RUN', 'PACKAGE_PRESERVATION': 'NOT_RUN',
        'FINAL_STATUS': 'M2.9_NOT_VERIFIED', 'BLOCKER_CLASS': 'ENVIRONMENT',
        'RAW_EVIDENCE': 'WITHHELD_FROM_PUBLIC_LOGS_AND_ARTIFACTS',
    }
    current = None
    try:
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        require(actual == SOURCE_HEAD, 'ENVIRONMENT')
        require(sys.version_info[:2] == (3, 12), 'ENVIRONMENT')
        result['python'] = '.'.join(map(str, sys.version_info[:3]))
        before_source = source_snapshot(root)
        for label, command in (
            ('pip_upgrade', [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip']),
            ('dependencies', [sys.executable, '-m', 'pip', 'install', '-r', 'requirements-tested.txt', '-e', '.']),
        ):
            require(execute(root, raw, label, command) == 0, 'ENVIRONMENT')
        before_packages = package_snapshot()
        result['packages'] = {k: v['version'] for k, v in before_packages.items()}
        pip_version = metadata.version('pip')
        require(re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:[a-z0-9]+)?', pip_version) is not None, 'ENVIRONMENT')
        require(all(re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:[a-z0-9]+)?', v) for v in result['packages'].values()), 'ENVIRONMENT')
        result['pip'] = pip_version
        current = 'PRE_GATE'
        result[current] = 'FAIL'
        require(execute(root, raw, 'compile', [sys.executable, '-m', 'compileall', '-q', 'app', 'tests', 'scripts']) == 0)
        require(execute(root, raw, 'collection', [sys.executable, '-m', 'pytest', '--collect-only', '-q']) == 0)
        result[current] = 'PASS'
        current = 'FOCUSED'
        result[current] = 'FAIL'
        code = execute(root, raw, 'focused', [sys.executable, '-m', 'pytest', MEMBERS[1], '-q', '-k', SELECTOR], True)
        result['focused_counts'] = test_results(raw / 'focused.xml', code, root)
        result[current] = 'PASS'
        current = 'SUPPLEMENTAL'
        result[current] = 'FAIL'
        code = execute(root, raw, 'supplemental', [sys.executable, '-m', 'pytest', MEMBERS[3], MEMBERS[4], MEMBERS[2], '-q'], True)
        result['supplemental_counts'] = test_results(raw / 'supplemental.xml', code, root)
        verify_a_contracts(raw / 'supplemental.xml')
        result[current] = 'PASS'
        for key in A_CONTRACTS:
            result[key] = 'PASS'
        current = None
        require(execute(root, raw, 'membership', [sys.executable, '-m', 'scripts.m2_test_membership']) == 0)
        require(tuple((raw / 'membership.log').read_text().splitlines()) == MEMBERS)
        # Discard stale tracked evidence so an interrupted run cannot reuse it.
        prefix = root / 'docs' / 'gen0_5A_M2_m29_resume_'
        for path in prefix.parent.glob(prefix.name + '*'):
            require(path.is_file())
            path.unlink()
        code = execute(root, raw, 'full_gate', [sys.executable, 'scripts/run_m2_stage_gate.py', 'm29', '--complete', SELECTOR, '--full'])
        def artifact(suffix: str) -> Path:
            return Path(str(prefix) + suffix)
        for tier in ('tier3', 'tier4'):
            if artifact(tier + '.exit').is_file() and artifact(tier + '.xml').is_file():
                tier_exit = int(artifact(tier + '.exit').read_text().strip())
                result[tier.upper()] = {'status': 'FAIL', 'passed': None, 'expected_missing': None, 'exit': tier_exit}
                counts = test_results(artifact(tier + '.xml'), tier_exit, root, ledger=True)
                result[tier.upper()] = {'status': 'PASS', **counts}
        require(code == 0)
        gate = json.loads(artifact('gate.json').read_text())
        require(gate['stage'] == 'm29' and gate['completed_selector'] == SELECTOR)
        require(tuple(gate['tier3_test_files']) == MEMBERS)
        require(artifact('RESULT.txt').read_text().strip() == 'STAGE_GATE_PASS_WITH_EXPLICIT_FUTURE_CONTRACTS')
        for tier in ('tier3', 'tier4'):
            require(result[tier.upper()]['status'] == 'PASS')
            require(gate[tier]['exit'] == result[tier.upper()]['exit'])
            require(gate[tier]['counts'] == {k: result[tier.upper()][k] for k in ('passed', 'expected_missing')})
        require(json.loads(artifact('source_preservation.json').read_text())['unchanged'] is True)
        require(before_source == source_snapshot(root))
        result['SOURCE_PRESERVATION'] = 'PASS'
        require(before_packages == package_snapshot())
        result['PACKAGE_PRESERVATION'] = 'PASS'
        result['FINAL_STATUS'] = 'M2.9_VERIFIED'
        result['BLOCKER_CLASS'] = 'NONE'
    except GateStop as exc:
        result['BLOCKER_CLASS'] = exc.category
        result['DIAGNOSIS'] = 'RAW_FAILURE_DETAILS_WITHHELD; PRIVATE_REVIEW_REQUIRED'
    except Exception:
        # Never render exception text: it may contain private source or data.
        result['BLOCKER_CLASS'] = 'GATE_INFRASTRUCTURE'
        result['DIAGNOSIS'] = 'RAW_FAILURE_DETAILS_WITHHELD; PRIVATE_REVIEW_REQUIRED'
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('```json\n' + text + '\n```\n')
    return 0 if result['FINAL_STATUS'] == 'M2.9_VERIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
