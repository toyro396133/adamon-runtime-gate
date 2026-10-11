"""Local signed append-only attempt chain; not remote ObjectLock proof.

Terminal/partial records are preserved, never replaced by a retry. SQLite
triggers deny ordinary UPDATE/DELETE; a privileged filesystem writer remains
outside this local storage threat boundary. Reviewers verify every signature
and prior digest, not merely the last row.
"""
import base64
import json
import re
import sqlite3
from .evidence import canonical, sha, HEX, StorageFailure
DOMAIN=b'ADAMON-T3-ATTEMPT-CHAIN-V1\x00'
ID=re.compile(r'^[A-Za-z0-9_-]{1,80}$')
STATES={'STARTED','SEALED_PARTIAL','CRASH_INCOMPLETE','SEALED_COMPLETE','CANCELLED'}


def validate_record(record):
    if type(record) is not dict or set(record)!={'campaign_id','attempt_id','subject_id','state','source_sha256','inventory_sha256'}:
        raise StorageFailure('closed attempt record required')
    if any(type(record[k]) is not str or not ID.fullmatch(record[k]) for k in ('campaign_id','attempt_id','subject_id')):
        raise StorageFailure('invalid attempt identity')
    if record['state'] not in STATES:raise StorageFailure('invalid attempt state; PASS forbidden')
    if type(record['source_sha256']) is not str or not HEX.fullmatch(record['source_sha256']):raise StorageFailure('invalid source digest')
    inventory=record['inventory_sha256']
    if record['state']=='STARTED':
        if inventory is not None:raise StorageFailure('started attempt has no sealed inventory')
    elif type(inventory) is not str or not HEX.fullmatch(inventory):raise StorageFailure('sealed inventory digest required even for partial evidence')


class AttemptChain:
    def __init__(self,path,*,signer,key_id):
        self.path=path;self.signer=signer;self.key_id=key_id
        with sqlite3.connect(path) as c:
            c.executescript('CREATE TABLE IF NOT EXISTS attempts(seq INTEGER PRIMARY KEY, envelope BLOB NOT NULL, digest TEXT UNIQUE NOT NULL); CREATE TRIGGER IF NOT EXISTS attempts_no_update BEFORE UPDATE ON attempts BEGIN SELECT RAISE(ABORT,"append only"); END; CREATE TRIGGER IF NOT EXISTS attempts_no_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,"append only"); END;')
    def append(self,record):
        validate_record(record)
        with sqlite3.connect(self.path) as c:
            c.execute('BEGIN IMMEDIATE')
            entries=[json.loads(row[0]) for row in c.execute('SELECT envelope FROM attempts ORDER BY seq')]
            verify_chain(entries,self.signer.public_key(),self.key_id)
            own=[e['record'] for e in entries if all(e['record'][k]==record[k] for k in ('campaign_id','attempt_id','subject_id'))]
            if (not own and record['state']!='STARTED') or (own and (len(own)!=1 or record['state']=='STARTED' or own[0]['source_sha256']!=record['source_sha256'])):
                raise StorageFailure('attempt must start once then terminate once; retry requires new attempt ID')
            payload={'version':1,'sequence':len(entries)+1,'previous_sha256':sha(canonical(entries[-1])) if entries else None,'record':record,'signer_key_id':self.key_id}
            envelope={**payload,'signature':base64.b64encode(self.signer.sign(DOMAIN+canonical(payload))).decode('ascii')}
            c.execute('INSERT INTO attempts VALUES(?,?,?)',(payload['sequence'],canonical(envelope),sha(canonical(envelope))))
            return envelope
    def read(self):
        with sqlite3.connect(f'file:{self.path}?mode=ro',uri=True) as c:
            c.execute('PRAGMA query_only=ON')
            entries=[json.loads(r[0]) for r in c.execute('SELECT envelope FROM attempts ORDER BY seq')]
        verify_chain(entries,self.signer.public_key(),self.key_id)
        return entries


def verify_chain(entries,key,key_id,*,expected_head_sha256=None,expected_record_count=None):
    prior=None; seen={}
    for number,envelope in enumerate(entries,1):
        if type(envelope) is not dict or set(envelope)!={'version','sequence','previous_sha256','record','signer_key_id','signature'}:
            raise StorageFailure('closed attempt envelope required')
        if type(envelope['version']) is not int or envelope['version']!=1 or type(envelope['sequence']) is not int or envelope['sequence']!=number or envelope['previous_sha256']!=prior or envelope['signer_key_id']!=key_id:
            raise StorageFailure('attempt chain reorder/truncation/binding mismatch')
        validate_record(envelope['record'])
        payload={k:v for k,v in envelope.items() if k!='signature'}
        try:key.verify(base64.b64decode(envelope['signature'],validate=True),DOMAIN+canonical(payload))
        except Exception as error:raise StorageFailure('invalid attempt signature') from error
        r=envelope['record']; ident=tuple(r[k] for k in ('campaign_id','attempt_id','subject_id'))
        old=seen.get(ident)
        if (old is None and r['state']!='STARTED') or (old is not None and (old['state']!='STARTED' or r['state']=='STARTED' or r['source_sha256']!=old['source_sha256'])):
            raise StorageFailure('invalid attempt transition')
        seen[ident]=r;prior=sha(canonical(envelope))
    if expected_head_sha256 is not None and prior!=expected_head_sha256:
        raise StorageFailure('externally pinned attempt head mismatch')
    if expected_record_count is not None and (type(expected_record_count) is not int or len(entries)!=expected_record_count):
        raise StorageFailure('externally pinned attempt record count mismatch')
    return {'record_count':len(entries),'head_sha256':prior,'scope':'LOCAL_SIGNED_CHAIN_NOT_REMOTE_RETENTION_PROOF'}
