import copy
import sqlite3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.attempts import AttemptChain,verify_chain
from infrastructure.t3.storage.evidence import StorageFailure


def record(attempt='one',state='STARTED'):
    return dict(campaign_id='campaign',attempt_id=attempt,subject_id='D1',state=state,source_sha256='a'*64,inventory_sha256=None if state=='STARTED' else 'b'*64)


def test_actual_sqlite_signatures_preserve_partial_and_retry(tmp_path):
    key=Ed25519PrivateKey.generate();path=tmp_path/'attempts.sqlite'
    chain=AttemptChain(path,signer=key,key_id='key')
    chain.append(record());chain.append(record(state='CRASH_INCOMPLETE'))
    with pytest.raises(StorageFailure):chain.append(record(state='SEALED_COMPLETE'))
    chain.append(record('two'));chain.append(record('two','SEALED_COMPLETE'))
    rows=chain.read();assert len(rows)==4 and rows[1]['record']['state']=='CRASH_INCOMPLETE'
    with sqlite3.connect(path) as c:
        for sql in ('DELETE FROM attempts','UPDATE attempts SET digest="x"'):
            with pytest.raises(sqlite3.IntegrityError):c.execute(sql)
    for changed in (rows[::-1],rows[1:],copy.deepcopy(rows)):
        if changed==rows:changed[1]['record']['state']='SEALED_COMPLETE'
        with pytest.raises(StorageFailure):verify_chain(changed,key.public_key(),'key')
    head=verify_chain(rows,key.public_key(),'key')['head_sha256']
    with pytest.raises(StorageFailure):verify_chain(rows[:-1],key.public_key(),'key',expected_head_sha256=head,expected_record_count=4)
    assert chain.read()==rows


def test_chain_rejects_pass_and_missing_inventory(tmp_path):
    key=Ed25519PrivateKey.generate();chain=AttemptChain(tmp_path/'a',signer=key,key_id='key')
    with pytest.raises(StorageFailure):chain.append(record(state='PASS'))
    with pytest.raises(StorageFailure):chain.append(record(state='SEALED_COMPLETE'))
    chain.append(record())
    bad=record(state='SEALED_PARTIAL');bad['inventory_sha256']=None
    with pytest.raises(StorageFailure):chain.append(bad)
