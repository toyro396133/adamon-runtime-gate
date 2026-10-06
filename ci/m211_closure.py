"""Exact-candidate closure; only numeric certificates enter public evidence."""
from pathlib import Path
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time
import urllib.request
from runtime_gate import GateStop, MEMBERS, package_snapshot, require, source_snapshot, test_results, verify_a_contracts

HEAD = '70e84601290e81d6ccb55b9b2f08c49f6c5b603d'
root = Path(sys.argv[1]).resolve()
raw = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'adamon-private-evidence'
raw.mkdir(mode=0o700, parents=True, exist_ok=False)
environment = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN', 'SECRET', 'PASSWORD'))}
environment['PYTHONPATH'] = str(root)
result = {'SOURCE_HEAD': HEAD, 'FINAL_STATUS': 'M2.11_NOT_VERIFIED', 'BLOCKER_CLASS': 'NONE',
          'TIER3': {'status': 'NOT_RUN'}, 'TIER4': {'status': 'NOT_RUN'},
          'SOURCE_PRESERVATION': 'NOT_RUN', 'PACKAGE_PRESERVATION': 'NOT_RUN',
          'RAW_EVIDENCE': 'PRIVATE_RUNNER_ONLY', 'certificates': {},
          'runtime_run_id': os.environ.get('GITHUB_RUN_ID'),
          'runtime_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
          'infrastructure_head': os.environ.get('GITHUB_SHA')}

def run(label, command, xml=False):
    env = dict(environment)
    env['PYTEST_ADDOPTS'] = '--junitxml=' + str(raw / (label + '.xml')) if xml else ''
    start = time.monotonic()
    print(label + ': START', flush=True)
    with (raw / (label + '.log')).open('wb') as stream:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
        while True:
            try:
                code = process.wait(timeout=30)
                break
            except subprocess.TimeoutExpired:
                print(label + ': RUNNING elapsed_seconds=' + str(int(time.monotonic() - start)), flush=True)
    (raw / (label + '.exit')).write_text(str(code) + '\n')
    certificate = {'exit': code, 'elapsed_seconds': round(time.monotonic() - start, 2)}
    for suffix in ('log', 'xml', 'exit'):
        path = raw / (label + '.' + suffix)
        if path.is_file():
            certificate[suffix + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    result['certificates'][label] = certificate
    print(label + ': END exit=' + str(code), flush=True)
    return code

def tests(label, targets, selector=None, ledger=False):
    command = [sys.executable, '-m', 'pytest', *targets, '-q', '--basetemp=' + str(raw / ('fixtures-' + label))]
    if selector:
        command += ['-k', selector]
    code = run(label, command, True)
    counts = test_results(raw / (label + '.xml'), code, root, ledger=ledger)
    if ledger:
        import xml.etree.ElementTree as ET
        failures = ET.parse(raw / (label + '.xml')).getroot().findall('.//failure')
        require(len(failures) == 13)
        require(all('EXPECTED_MISSING_CAPABILITY: M2 open_from_trigger' in (f.get('message', '') + (f.text or '')) for f in failures))
    print(label + ': ACCEPTED ' + json.dumps(counts, sort_keys=True), flush=True)
    return {'status': 'PASS', **counts}

try:
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip() == HEAD, 'ENVIRONMENT')
    require(sys.version_info[:2] == (3, 12), 'ENVIRONMENT')
    before = source_snapshot(root)
    require(run('dependencies', [sys.executable, '-m', 'pip', 'install', '-r', 'requirements-tested.txt', '-e', '.']) == 0, 'ENVIRONMENT')
    packages = package_snapshot()
    result['python'] = '.'.join(map(str, sys.version_info[:3]))
    result['packages'] = {name: value['version'] for name, value in packages.items()}
    require(run('compile', [sys.executable, '-m', 'compileall', '-q', 'app', 'tests', 'scripts']) == 0)
    require(run('collection', [sys.executable, '-m', 'pytest', '--collect-only', '-q']) == 0)
    result['tiny'] = tests('tiny', [MEMBERS[1]], 'W6_record_merge_preserves_historical_worlds')
    require(result['tiny']['passed'] == 2)
    result['focused'] = tests('focused', [MEMBERS[1]], 'W7 or transfer')
    require(result['focused']['passed'] == 54)
    result['w6_regression'] = tests('w6_regression', [MEMBERS[1]], 'W6')
    require(result['w6_regression']['passed'] == 61)
    guard_program = '''import runpy, tempfile
from pathlib import Path
from app.persistence.database import Database
from app.organization.models import Ref, FUNCTIONAL
from app.organization import rules
m = runpy.run_path('tests/integration/test_organization_m2.py')
with tempfile.TemporaryDirectory(prefix='cognitive-zero-m211-guards-') as d:
 db = Database(Path(d) / 'state.sqlite')
 try:
  f, result, target, sources = m['merge_publication'](db)
  e, actor, p, objs, seeds, ws, ev = f
  before = m['snapshot'](db)
  try: e.relate(actor, Ref('perception','world',target), Ref('perception','world',ws[0]), 'merged_from', evidence=ev[0], relation_level='organization')
  except ValueError as exc: assert str(exc) == 'transition requires validated paired publication'
  else: raise AssertionError('manual transition allowed')
  assert m['snapshot'](db) == before
  ids = e.record_world_merge(actor, target, sources, result['digest'])
  before = m['snapshot'](db)
  for id in ids:
   try: e.revise_relation(actor, id, 'rejected', counterevidence=ev[1])
   except ValueError as exc: assert str(exc) == 'immutable membership/transition'
   else: raise AssertionError('transition revision allowed')
   assert m['snapshot'](db) == before
  assert 'merged_from' not in FUNCTIONAL
  calls = []
  original = rules.audit_merge_pair
  def observed(*args, **kwargs):
   calls.append(True)
   return original(*args, **kwargs)
  rules.audit_merge_pair = observed
  try: m['audit'](db)
  finally: rules.audit_merge_pair = original
  assert calls
 finally: db.close()
'''
    require(run('writer_guards', [sys.executable, '-c', guard_program]) == 0)
    result['WRITER_REJECTION_CONTRACTS'] = 'PASS'
    result['VERIFIER_REACHES_AUDIT_MERGE_PAIR'] = 'PASS'
    result['supplemental'] = tests('supplemental', [MEMBERS[2], MEMBERS[3], MEMBERS[4]])
    verify_a_contracts(raw / 'supplemental.xml')
    result.update({'A-001': 'PASS', 'A-002': 'PASS', 'A-003': 'PASS'})
    require(run('membership', [sys.executable, '-m', 'scripts.m2_test_membership']) == 0)
    require(tuple((raw / 'membership.log').read_text().splitlines()) == MEMBERS)
    result['tier3_test_files'] = list(MEMBERS)
    result['TIER3'] = tests('tier3', list(MEMBERS), ledger=True)
    result['TIER4'] = tests('tier4', [], ledger=True)
    require(source_snapshot(root) == before)
    result['SOURCE_PRESERVATION'] = 'PASS'
    require(package_snapshot() == packages)
    result['PACKAGE_PRESERVATION'] = 'PASS'
    result['source_manifest_sha256'] = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    result['source_files'] = len(before)
    result['FINAL_STATUS'] = 'M2.11_VERIFIED'
except GateStop as exc:
    result['BLOCKER_CLASS'] = exc.category
except Exception:
    result['BLOCKER_CLASS'] = 'GATE_INFRASTRUCTURE'

text = json.dumps(result, indent=2, sort_keys=True)
(raw / 'summary.json').write_text(text + '\n')
print(text, flush=True)
summary = os.environ.get('GITHUB_STEP_SUMMARY')
if summary:
    with open(summary, 'a') as stream:
        stream.write('```json\n' + text + '\n```\n')
# Save only the numeric/hash certificate in the public infrastructure repository.
# The private read credential is never used to publish evidence.
token = os.environ.get('EVIDENCE_TOKEN')
if token:
    import base64
    payload = json.dumps({'message': 'docs: record M2.11 closure certificate',
                          'content': base64.b64encode((text + '\n').encode()).decode(),
                          'branch': 'main'}).encode()
    url = 'https://api.github.com/repos/toyro396133/adamon-runtime-gate/contents/evidence/m211/' + HEAD + '.json'
    request = urllib.request.Request(url, data=payload, method='PUT', headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.status == 201)
        print('numeric_certificate: SAVED', flush=True)
    except Exception:
        print('numeric_certificate: SAVE_FAILED', flush=True)
        raise SystemExit(1)
raise SystemExit(0 if result['FINAL_STATUS'] == 'M2.11_VERIFIED' else 1)
