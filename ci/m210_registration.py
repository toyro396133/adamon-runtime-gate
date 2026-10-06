"""Public infrastructure: frozen private preimplementation registration."""
from pathlib import Path
import json, os, subprocess, sys, time
from runtime_gate import source_snapshot, package_snapshot, test_results, MEMBERS
HEAD = "5980ed4adb94a64a0eef450c151e4b7aa5b62ee3"
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
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=root).decode().strip() == HEAD
before = source_snapshot(root)
assert run("dependencies",[sys.executable,"-m","pip","install","-r","requirements-tested.txt","-e","."]) == 0
packages = package_snapshot()
assert run("compile",[sys.executable,"-m","compileall","-q","app","tests","scripts"]) == 0
assert run("collection",[sys.executable,"-m","pytest","--collect-only","-q"]) == 0
code = run("registration",[sys.executable,"-m","pytest",MEMBERS[1],"-q","-k","W6"],True)
counts = test_results(raw/"registration.xml",code,root,ledger=True)
cases = __import__("xml.etree.ElementTree",fromlist=[""]).parse(raw/"registration.xml").getroot()
controls = [c for c in cases.iter("testcase") if c.attrib["name"].startswith("test_W6_phase_b_without_phase_c_claims_no_merge")]
assert len(controls) == 1 and all(c.find("failure") is None for c in controls)
assert source_snapshot(root) == before
assert package_snapshot() == packages
result = {"STATUS":"M2.10_REGISTRATION_PASS","SOURCE_HEAD":HEAD,"counts":counts,"PHASE_B_CONTROL":"PASS","SOURCE_PRESERVATION":"PASS","PACKAGE_PRESERVATION":"PASS"}
print(json.dumps(result,sort_keys=True),flush=True)
with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as f: f.write("\n```json\n"+json.dumps(result,indent=2)+"\n```\n")
