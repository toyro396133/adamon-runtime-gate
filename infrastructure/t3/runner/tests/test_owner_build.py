"""Small real child execution; never a Runner build or research history."""
import json
import sys
from pathlib import Path
import pytest
from infrastructure.t3.runner import owner_build as module


def test_environment_is_closed(tmp_path, monkeypatch):
    monkeypatch.setenv('MSBuildSDKsPath','malicious')
    monkeypatch.setenv('NUGET_PACKAGES','/ambient')
    env=module.environment(tmp_path,sys.executable)
    assert 'MSBuildSDKsPath' not in env
    assert env['NUGET_PACKAGES']==str(tmp_path/'packages')
    assert 'PYTHONPATH' not in env
    assert env['PATH'].split(':')[0]==str(Path(sys.executable).resolve().parent)


def setup_driver(tmp_path,monkeypatch,code):
    root=tmp_path/'source';root.mkdir()
    bundle={'commands':[{'phase':'test_child','argv':[sys.executable,'-c',code]}]}
    # Explicit test-only authority adapter. Production validates pinned graph/SDK.
    monkeypatch.setattr(module,'validate_bundle',lambda *args:None)
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:type('Usage',(),{'free':32*1024**3})())
    return bundle,root,tmp_path/'output'


def test_real_child_failed_log_and_exit_preserved(tmp_path,monkeypatch):
    bundle,root,out=setup_driver(tmp_path,monkeypatch,"import sys;print('original failure');sys.exit(7)")
    result=module.run(bundle,root,sys.executable,tmp_path,out)
    assert result['exit_code']==7
    assert (out/'test_child.log').read_bytes()==b'original failure\n'
    receipt=json.loads((out/'partial-receipt.json').read_bytes())
    assert receipt['phases']['test_child']['argv']==bundle['commands'][0]['argv']
    assert not (out/'receipt.json').exists()


def test_real_child_timeout_retains_partial(tmp_path,monkeypatch):
    bundle,root,out=setup_driver(tmp_path,monkeypatch,"import time;print('started',flush=True);time.sleep(20)")
    result=module.run(bundle,root,sys.executable,tmp_path,out,timeout=1)
    assert result['exit_code']==124
    assert (out/'test_child.log').read_bytes()==b'started\n'


def test_no_retry_on_low_capacity(tmp_path,monkeypatch):
    bundle,root,out=setup_driver(tmp_path,monkeypatch,"raise Exception('must not start')")
    monkeypatch.setattr(module.shutil,'disk_usage',lambda path:type('Usage',(),{'free':1})())
    with pytest.raises(ValueError,match='CAPACITY'):
        module.run(bundle,root,sys.executable,tmp_path,out)
    assert not out.exists()


def test_existing_original_output_never_overwritten(tmp_path):
    out=tmp_path/'original';out.mkdir();(out/'evidence').write_bytes(b'original')
    with pytest.raises(ValueError,match='OUTPUT_EXISTS'):
        module.run({},tmp_path,sys.executable,tmp_path,out)
    assert (out/'evidence').read_bytes()==b'original'


def test_missing_material_inventory_is_deterministic(tmp_path):
    root=tmp_path/'checkout';project=root/'src/Test';project.mkdir(parents=True)
    (root/'src/ActionsRunner.sln').write_text(r'Test\Test.csproj')
    (project/'Test.csproj').write_text('<Project/>')
    assert module.missing_materials(root,tmp_path/'feed')==['src/Test/packages.lock.json']
    (project/'packages.lock.json').write_text(json.dumps({'dependencies':{'net8.0':{'Example':{'type':'Direct','resolved':'1.2.3'}}}}))
    assert module.missing_materials(root,tmp_path/'feed')==['feed/example.1.2.3.nupkg']
