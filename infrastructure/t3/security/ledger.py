"""One authoritative SQLite ledger, never a separately granting local mirror."""
import sqlite3
import time
from types import MappingProxyType
from .protocol import Denied, canonical, digest, verify

class Ledger:
    def __init__(self, path, owner_keys, payload_validator, clock=time.time):
        self.path, self.keys, self.clock = path, MappingProxyType(dict(owner_keys)), clock
        self.payload_validator = payload_validator
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS permits(
              id TEXT PRIMARY KEY, campaign TEXT NOT NULL, role TEXT NOT NULL,
              subject TEXT NOT NULL, attempt INTEGER NOT NULL, payload BLOB NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('ISSUED','CONSUMED','REVOKED')),
              session TEXT, lease INTEGER, UNIQUE(campaign,role,subject,attempt));
              CREATE TABLE IF NOT EXISTS events(
              n INTEGER PRIMARY KEY, previous TEXT NOT NULL, entry BLOB NOT NULL, hash TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS revocations(id TEXT PRIMARY KEY, epoch INTEGER NOT NULL);''')
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA journal_mode=WAL')
        return db
    def event(self, db, value):
        row = db.execute('SELECT hash FROM events ORDER BY n DESC LIMIT 1').fetchone()
        previous = row[0] if row else '0'*64
        body = canonical(value)
        import hashlib
        hash_value = hashlib.sha256(previous.encode()+body).hexdigest()
        db.execute('INSERT INTO events(previous,entry,hash) VALUES(?,?,?)',(previous,body,hash_value))
    def issue(self, envelope):
        p = verify(envelope, self.keys, 'ADAMON-P4V3-PERMIT')
        self.payload_validator(p)
        if "issuer_key_id" in p and p["issuer_key_id"] != envelope["key_id"]: raise Denied("issuer mismatch")
        now = int(self.clock())
        if p.get('version') != 4 or p.get('role') not in {'LIFE','MICRO','AUDIT','AGGREGATION'}:
            raise Denied('version/role')
        for key in ('issued_at','not_before','expires_at','execution_deadline','attempt'):
            if type(p.get(key)) is not int: raise Denied('integer required')
        if not p['issued_at'] <= p['not_before'] < p['expires_at'] <= p['issued_at']+900:
            raise Denied('invalid permit window')
        if not p['not_before'] <= now < p['expires_at'] or p['issued_at'] > now+30:
            raise Denied('permit outside validity')
        if p['execution_deadline'] <= now: raise Denied('execution deadline')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                if db.execute('SELECT 1 FROM revocations WHERE id=?',(p['permit_id'],)).fetchone():
                    raise Denied('revoked')
                db.execute('INSERT INTO permits VALUES(?,?,?,?,?,?,?,NULL,NULL)',
                           (p['permit_id'],p['authority_sha256'],p['role'],p['subject'],p['attempt'],canonical(p),'ISSUED'))
                self.event(db,dict(action='ISSUED',permit=p['permit_id'],digest=digest(p)))
                db.commit()
            except Exception:
                db.rollback()
                raise
        return p
    def consume(self, permit_id, binding, session):
        """Caller supplies trusted verified process+TLS binding, never untrusted JSON."""
        now = int(self.clock())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute('SELECT payload,state FROM permits WHERE id=?',(permit_id,)).fetchone()
                if row is None or row[1] != 'ISSUED': raise Denied('not issued')
                from .protocol import decode
                p = decode(row[0])
                if not p['not_before'] <= now < p['expires_at'] or now>=p['execution_deadline']: raise Denied('expired/deadline')
                if not binding or any(k not in p or canonical(p[k]) != canonical(v) for k,v in binding.items()): raise Denied('binding mismatch')
                metadata = {'version','permit_id','issuer_key_id','attempt','issued_at','not_before','expires_at','execution_deadline','revocation_epoch'}
                required = set(p) - metadata
                if not required <= binding.keys(): raise Denied('incomplete binding')
                if db.execute('SELECT 1 FROM revocations WHERE id=?',(permit_id,)).fetchone(): raise Denied('revoked')
                lease = min(now+60,p['execution_deadline'])
                changed = db.execute("UPDATE permits SET state='CONSUMED',session=?,lease=? WHERE id=? AND state='ISSUED'",(session,lease,permit_id)).rowcount
                if changed != 1: raise Denied('race')
                self.event(db,dict(action='CONSUMED',permit=permit_id,session=session,binding=digest(binding),lease=lease))
                db.commit()
                return p
            except Exception:
                db.rollback()
                raise
    def renew(self, permit_id, session, verified_job_live=False):
        if verified_job_live is not True: raise Denied('Job check unavailable')
        now = int(self.clock())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT payload,state,session,lease FROM permits WHERE id=?',(permit_id,)).fetchone()
            if not row or row[1]!='CONSUMED' or row[2]!=session or now>=row[3]:
                db.rollback(); raise Denied('lease/session')
            from .protocol import decode
            deadline=decode(row[0])['execution_deadline']
            if now>=deadline: db.rollback(); raise Denied('deadline')
            db.execute('UPDATE permits SET lease=? WHERE id=?',(min(now+60,deadline),permit_id))
            self.event(db,dict(action='RENEW',permit=permit_id,session=session))
            db.commit()
    def revoke(self, envelope):
        p=verify(envelope,self.keys,'ADAMON-P4V3-REVOKE')
        if set(p)!={'permit_id','epoch','reason'} or type(p['epoch']) is not int or p['epoch']<1:
            raise Denied('revocation shape')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT epoch FROM revocations WHERE id=?',(p['permit_id'],)).fetchone()
            if old and p['epoch']<=old[0]: db.rollback(); raise Denied('stale revocation')
            db.execute('INSERT INTO revocations VALUES(?,?) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch',(p['permit_id'],p['epoch']))
            db.execute("UPDATE permits SET state='REVOKED',lease=0 WHERE id=?",(p['permit_id'],))
            self.event(db,dict(action='REVOKED',**p)); db.commit()
    def verify_chain(self):
        import hashlib
        previous='0'*64
        with self.connect() as db:
            for prev,entry,current in db.execute('SELECT previous,entry,hash FROM events ORDER BY n'):
                if prev!=previous or hashlib.sha256(prev.encode()+entry).hexdigest()!=current: raise Denied('ledger chain')
                previous=current
        return previous
    def session_live(self, permit_id, session):
        """Read authoritative consumed lease; cannot grant or renew authority."""
        from .protocol import decode
        now=int(self.clock())
        with self.connect() as db:
            row=db.execute('SELECT payload,state,session,lease FROM permits WHERE id=?',(permit_id,)).fetchone()
            revoked=db.execute('SELECT 1 FROM revocations WHERE id=?',(permit_id,)).fetchone()
        return bool(row and not revoked and row[1]=='CONSUMED' and row[2]==session and now<row[3] and now<decode(row[0])['execution_deadline'])
    def end_session(self, permit_id, session, reason):
        """Local supervisor may reduce consumed authority, never issue/reissue it."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed=db.execute("UPDATE permits SET lease=0 WHERE id=? AND state='CONSUMED' AND session=?",(permit_id,session)).rowcount
            if changed:
                self.event(db,dict(action='SESSION_ENDED',permit=permit_id,session=session,reason=reason))
            db.commit()
        return bool(changed)

    def require_issued(self,permit_id,binding):
        """Read-only pre-delivery check, never consumes or grants a session.

        Full signed-payload bindings must be present. Caller must still perform
        channel challenge and atomic consume; another consumer wins the race.
        """
        from .protocol import decode
        now=int(self.clock())
        with self.connect() as db:
            row=db.execute('SELECT payload,state FROM permits WHERE id=?',(permit_id,)).fetchone()
            if row is None or row[1]!='ISSUED':raise Denied('bootstrap permit not issued')
            if db.execute('SELECT 1 FROM revocations WHERE id=?',(permit_id,)).fetchone():raise Denied('bootstrap permit revoked')
            p=decode(row[0])
            if not p['not_before']<=now<p['expires_at'] or now>=p['execution_deadline']:raise Denied('bootstrap permit expired')
            metadata={'version','permit_id','issuer_key_id','attempt','issued_at','not_before','expires_at','execution_deadline','revocation_epoch'}
            if not set(p)-metadata<=binding.keys() or any(k not in p or canonical(p[k])!=canonical(v) for k,v in binding.items()):
                raise Denied('bootstrap permit full binding mismatch')
            return MappingProxyType(p)
