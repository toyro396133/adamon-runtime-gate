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
    import tarfile
    cert = raw/"recipient.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nMIIFITCCAwmgAwIBAgIUF653mDLHAG0v1vTvmrdOqATRkYQwDQYJKoZIhvcNAQEL\nBQAwIDEeMBwGA1UEAwwVbTIxMC1wcml2YXRlLWV2aWRlbmNlMB4XDTI2MTAwNjE4\nMzUxMloXDTI2MTAxMzE4MzUxMlowIDEeMBwGA1UEAwwVbTIxMC1wcml2YXRlLWV2\naWRlbmNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4NPz2/QQ3xkj\nNcDWsTXQNUbrt0PG9aHzGBjEBOKQeB063+Ky/N2hecp59W9h89rYCpv3AsHonVKO\nlknliVQAfS57RzbYtsm9kAURxhnIwTVciMCoMahXdalH9GMSCCrv6NPLay5qWEFC\naBDRqBdAOr00oCh+uhb6bfP88jQpavJ7lZvnakDYBK+mIv2qLIYUdKn3luwCj47G\nWeYrEF7WR42Tqdg6nQFAreftrQTu6Lqbplw6UExX0HFIts95SC/UCZEHmYfp49po\nTvWEiLXRz0/DDhL2pBC2aL3pxbu+AXJ3P32eWhcdqyCLSo00EWfiRz2xg6ELDa/T\n7ctJdEBnOsuA2dPjjiiWyFU+umnCCaqrGMgs0ms5ric4aEm0glyyrF/pQUilqdWC\n1RrzqrkQzTeMBICFgfN+Q9SbDxlHFQ0JnqPqdKEvDS9ejl+FvqxoVIolLCq8iKWx\nnQu0yiilH1A9B5L+jV2EKU6BoCyF/dXyt+n6lV1dcQzQNOytONSzu5wNlPttJHzu\nRqFAChfdPNw9xkWNADfhksflOoFO1zbm/52We7+xaBi0UBLP58GSUCJZiKcHv3EE\nq35AHFpg9FlJsrDvwqlBS59M+ldcbxNuxmQ5gLyRL0aIAHZiBf0Qwy2lIL0CTqle\nOhr9h92ixW6AJoURxmlFLmXseXhhbTsCAwEAAaNTMFEwHQYDVR0OBBYEFEbRyy52\nRsbGESov+JziJqqYjdyZMB8GA1UdIwQYMBaAFEbRyy52RsbGESov+JziJqqYjdyZ\nMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGsPQ+rwrHdH+TYs\n+T5LMUDwgvQCk2tYdlVh6jliAGGkCdR19FniahLTeOV3MCH2HCxuJdgUHwqJaZ3B\neqW99zuLT4mAzOM7sUx4YIvwzJYrG4N9yN/IZhZ3Eu3uKmMLiwbKkIcrVmVq8bIV\nTRuNcWzUdUR+oAXSAA2SoKcoE9XpeBdh7dan51fRUlHYYzLw5xFSkth+5upy20pO\nHgKrnkTTlty69ZI5CsWtjcIRPwUixM4tmRi4mZ8dCVBHUSdyHeoqk3GUAQBsykQ0\n0wzwSYvR5Rkn3RdjQO8Cc2Zosw/G5E4bzB2BF3Ai20+7cT1D687d6WkAYcCUyXxd\nPVSYzxzZZ3GGMHvqP3Qc00dIAFckCBd18hnBcrkN+pGxlyF/SA8BY1whqDBUBmU8\nJDaJO0EP+fWPifNkBkwwuxKGiSPYdkckmf0y3HIAMVLiawd9KT6rd743qNdLW+hh\n78K3Al2AoiADgSph3rCyz1uuBWkEO7ASwUtQ+/fCFucDO4/7ctHDvXUUgQm3I/nZ\nRdZsccpNOgmKFZIkIWi4315JpzDkPW/g6OevGfRTwwq1WOtnNvdX10P1J9AhGhG0\nqr65jt/PwqI6kmxR1j9P1NM/hwJ/KRUGtlMgRNCkOkzm7HmU/HErfd4dXnHt/amQ\nc2ReSkif+Ha5QUxFORFX9fDi1upx\n-----END CERTIFICATE-----\n")
    archive = raw/"private-evidence.tar.gz"
    with tarfile.open(archive,"w:gz") as tar:
        for path in raw.iterdir():
            if path != archive: tar.add(path,arcname=path.name)
    dest = Path(os.environ["RUNNER_TEMP"])/"m210-encrypted-evidence"
    dest.mkdir(mode=0o700,exist_ok=True)
    subprocess.run(["openssl","cms","-encrypt","-binary","-aes-256-cbc","-in",str(archive),"-out",str(dest/"evidence.cms"),"-outform","DER",str(cert)],check=True)
