"""Closed static owner handoff; does not provision, authorize or dispatch."""
import copy
import json
from pathlib import Path
import pytest
from infrastructure.t3.preflight.owner_bundle import create,main
from infrastructure.t3.preflight.sequence import GATES


def context():
    return dict(version=1,private_commit='a'*40,public_commit='b'*40,
        authority_sha256='c'*64,mke2fs_sha256='d'*64,
        source_fingerprints={'private':{'infrastructure/t3/capture.py':'e'*64},
                             'public':{'infrastructure/t3/runtime/guest.py':'f'*64}})


def test_exact_existing_gates_and_no_authorization():
    bundle=create(context())
    assert [row['gate'] for row in bundle['gates']]==list(GATES)
    assert all(row['status']=='BLOCKED_OWNER_APPROVAL' for row in bundle['gates'])
    assert not bundle['execution_authorized'] and not bundle['is_execution_freeze']
    assert not any(bundle['runtime_constraints'][name] for name in
        ('workflow_installation_authorized','live_dispatch_authorized','provision_authorized',
         'research_authorized','terminal_pass_signing_authorized'))
    assert bundle['minimum_host']['free_disk_bytes']==512*1024**3
    assert bundle['retention']['minimum_days']==365
    assert create(context())==bundle


@pytest.mark.parametrize('field,value',[('private_commit','main'),('public_commit',True),
    ('authority_sha256','latest'),('mke2fs_sha256','unverified'),('version',True),
    ('source_fingerprints',{'private':{},'public':{}})])
def test_unknown_or_unpinned_candidate_rejected(field,value):
    data=context();data[field]=value
    with pytest.raises(ValueError):create(data)


def test_arbitrary_command_and_source_path_rejected():
    data=context();data['command']='shell'
    with pytest.raises(ValueError):create(data)
    data=context();data['source_fingerprints']['public']={'../secret':'f'*64}
    with pytest.raises(ValueError):create(data)


def test_cli_exclusive_local_output(tmp_path):
    source=tmp_path/'context.json';source.write_text(json.dumps(context()))
    output=tmp_path/'bundle.json'
    assert main(['--context',str(source),'--output',str(output)])==0
    assert json.loads(output.read_text())['execution_authorized'] is False
    with pytest.raises(FileExistsError):main(['--context',str(source),'--output',str(output)])


def test_generated_argv_flags_exist_in_actual_program_parsers():
    # The owner package must not advertise a fictitious --sha256-file option.
    from infrastructure.t3.deployment import rootfs_build
    code=Path(rootfs_build.__file__).read_text()
    command=next(row for row in create(context())['commands'] if row['name']=='nonresearch_rootfs')
    assert '--mke2fs-sha256' in command['argv']
    assert '--mke2fs-sha256-file' not in command['argv']
    assert "'mke2fs-sha256'" in code
