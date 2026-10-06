"""Public infrastructure: frozen private preimplementation registration."""
from pathlib import Path
import json, os, subprocess, sys, time
from runtime_gate import source_snapshot, package_snapshot, test_results, MEMBERS
HEAD = "cddde8a66df9de31aa28b2cb5f0aa827aeef1d6d"
root = Path(sys.argv[1]).resolve()
raw = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "adamon-private-evidence"
raw.mkdir(mode=0o700, parents=True, exist_ok=False)
env = {k:v for k,v in os.environ.items() if not any(s in k.upper() for s in ("TOKEN","SECRET","PASSWORD"))}
env["PYTHONPATH"] = str(root)
def run(label, args, xml=False):
    env["PYTEST_ADDOPTS"] = "--junitxml=" + str(raw/(label+".xml")) if xml else ""
    start = time.monotonic()
    print(label+": START", flush=True)
    with (raw/(label+".log")).open("wb") as out:
        p = subprocess.Popen(args, cwd=root, env=env, stdout=out, stderr=subprocess.STDOUT)
        while True:
            try: code = p.wait(timeout=30); break
            except subprocess.TimeoutExpired:
                print(label+": RUNNING elapsed_seconds="+str(int(time.monotonic()-start)), flush=True)
    (raw/(label+".exit")).write_text(str(code))
    print(label+": END exit="+str(code), flush=True)
    return code

try:
    assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=root).decode().strip() == HEAD
    before = source_snapshot(root)
    assert run("dependencies",[sys.executable,"-m","pip","install","-r","requirements-tested.txt","-e","."]) == 0
    packages = package_snapshot()
    assert run("compile",[sys.executable,"-m","compileall","-q","app","tests","scripts"]) == 0
    assert run("collection",[sys.executable,"-m","pytest","--collect-only","-q"]) == 0
    code = run("tiny",[sys.executable,"-m","pytest",MEMBERS[1],"-q","-k","W6_record_merge_preserves_historical_worlds"],True)
    tiny = test_results(raw/"tiny.xml",code,root)
    code = run("focused",[sys.executable,"-m","pytest",MEMBERS[1],"-q","-k","W6"],True)
    counts = test_results(raw/"focused.xml",code,root)
    assert source_snapshot(root) == before
    assert package_snapshot() == packages
    result = {"STATUS":"M2.10_FOCUSED_PASS","SOURCE_HEAD":HEAD,"tiny":tiny,"focused":counts,"SOURCE_PRESERVATION":"PASS","PACKAGE_PRESERVATION":"PASS"}
    print(json.dumps(result,sort_keys=True),flush=True)
    (raw/"summary.json").write_text(json.dumps(result,indent=2))
finally:
    pass  # Private raw evidence remains on the runner only; cleanup removes it.
