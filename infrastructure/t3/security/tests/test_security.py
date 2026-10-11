import concurrent.futures
import array
import hashlib
import os
import socket
import struct
import tempfile
import unittest
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.security.protocol import Denied, canonical, decode, sign, verify, Challenges
from infrastructure.t3.security.ledger import Ledger
from infrastructure.t3.security.bridge import receive, send
from infrastructure.t3.security.process import spawn_verified_launcher

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate(); self.keys={'owner':self.key.public_key()}
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.now=1000
        self.fields={'version','permit_id','authority_sha256','role','subject','attempt','issued_at','not_before','expires_at','execution_deadline','boot_id','dispatch_id','job_id','run_id','run_attempt','client_spki_sha256','request_sha256','assignment_sha256'}
        def validator(p):
            if set(p)!=self.fields: raise Denied('synthetic closed schema')
        self.ledger=Ledger(self.tmp.name+'/ledger.sqlite',self.keys,validator,lambda:self.now)
    def permit(self):
        p=dict(version=4,permit_id='synthetic',authority_sha256='a'*64,role='MICRO',subject='synthetic-control',attempt=1,issued_at=1000,not_before=1000,expires_at=1100,execution_deadline=2000,boot_id='boot',dispatch_id='dispatch',job_id=1,run_id=2,run_attempt=1,client_spki_sha256='b'*64,request_sha256='c'*64,assignment_sha256='d'*64)
        return p
    def binding(self,p):
        return {k:p[k] for k in ('authority_sha256','boot_id','dispatch_id','job_id','run_id','run_attempt','role','subject','client_spki_sha256','request_sha256','assignment_sha256')}
    def issue(self,p):
        return self.ledger.issue(sign(p,self.key,'owner','ADAMON-P4V3-PERMIT'))
    def test_real_signature_and_tampering(self):
        e=sign(self.permit(),self.key,'owner','ADAMON-P4V3-PERMIT')
        self.assertEqual(verify(e,self.keys,'ADAMON-P4V3-PERMIT'),self.permit())
        e['payload']['job_id']=3
        with self.assertRaises(Denied): verify(e,self.keys,'ADAMON-P4V3-PERMIT')
    def test_domain_and_unknown_signer(self):
        e=sign(self.permit(),self.key,'owner','wrong')
        with self.assertRaises(Denied): verify(e,self.keys,'ADAMON-P4V3-PERMIT')
        with self.assertRaises(Denied): verify(e,{},'wrong')
    def test_canonical_closed_encoding(self):
        for obj in (1.5,2**53,'עברית',{'x':float('nan')}):
            with self.assertRaises(Denied): canonical(obj)
        for raw in (b'{"a":1,"a":2}',b'{ "a":1}',b'\xef\xbb\xbf{}'):
            with self.assertRaises(Denied): decode(raw)
    def test_atomic_race_one_consume(self):
        p=self.issue(self.permit())
        def run(i):
            try: self.ledger.consume(p['permit_id'],self.binding(p),str(i)); return True
            except Denied: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            result=list(pool.map(run,range(8)))
        self.assertEqual(sum(result),1)
        self.assertEqual(len(self.ledger.verify_chain()),64)
    def test_crash_consumed_survives_reopen(self):
        p=self.issue(self.permit()); self.ledger.consume(p['permit_id'],self.binding(p),'s')
        reopened=Ledger(self.ledger.path,self.keys,self.ledger.payload_validator,lambda:self.now)
        with self.assertRaises(Denied): reopened.consume(p['permit_id'],self.binding(p),'s2')
    def test_expiry_binding_and_closed_fields(self):
        p=self.issue(self.permit())
        with self.assertRaises(Denied): self.ledger.consume(p['permit_id'],{},'s')
        wrong=self.binding(p); wrong['job_id']=55
        with self.assertRaises(Denied): self.ledger.consume(p['permit_id'],wrong,'s')
        self.now=1100
        with self.assertRaises(Denied): self.ledger.consume(p['permit_id'],self.binding(p),'s')
        p['shell']='anything'
        with self.assertRaises(Denied): self.issue(p)
    def test_boolean_is_not_numeric_job_binding(self):
        p=self.issue(self.permit()); binding=self.binding(p);binding['job_id']=True
        with self.assertRaises(Denied): self.ledger.consume(p['permit_id'],binding,'s')

    def test_signed_revocation_before_and_after_consume(self):
        p=self.issue(self.permit()); self.ledger.consume(p['permit_id'],self.binding(p),'s')
        rev=sign(dict(permit_id=p['permit_id'],epoch=1,reason='cancel'),self.key,'owner','ADAMON-P4V3-REVOKE')
        self.ledger.revoke(rev)
        with self.assertRaises(Denied): self.ledger.renew(p['permit_id'],'s',True)
        with self.assertRaises(Denied): self.ledger.revoke(rev)
        self.ledger.verify_chain()
    def test_renew_requires_live_job_and_lease(self):
        p=self.issue(self.permit()); self.ledger.consume(p['permit_id'],self.binding(p),'s')
        with self.assertRaises(Denied): self.ledger.renew(p['permit_id'],'s')
        self.ledger.renew(p['permit_id'],'s',True)
        self.now+=60
        with self.assertRaises(Denied): self.ledger.renew(p['permit_id'],'s',True)
    def test_challenge_real_signature_replay_and_expiry(self):
        ch=Challenges(lambda:self.now); key=Ed25519PrivateKey.generate()
        proof=ch.issue('s','e'*64,'f'*64)
        sig=sign(proof,key,'k','ADAMON-P4V3-CLIENT-PROOF')['signature']
        ch.consume(proof,sig,key.public_key())
        with self.assertRaises(Denied): ch.consume(proof,sig,key.public_key())
        proof=ch.issue('s','e'*64,'f'*64); self.now+=30
        with self.assertRaises(Denied): ch.consume(proof,sig,key.public_key())
    def test_bridge_real_socket_closed_role(self):
        a,b=socket.socketpair(); self.addCleanup(a.close);self.addCleanup(b.close)
        m=dict(version=1,operation='revoke',request_id=str(uuid.uuid4()),payload={'reason':'cancel'})
        send(a,m); self.assertEqual(receive(b,'WORKER'),(m,[]))
        m['version']=True;send(a,m)
        with self.assertRaises(Denied): receive(b,'WORKER')
        m['version']=1;m['operation']='shell';send(a,m)
        with self.assertRaises(Denied): receive(b,'WORKER')
    def test_native_scm_rights_fd_transfer(self):
        a,b=socket.socketpair(); self.addCleanup(a.close);self.addCleanup(b.close)
        r,w=os.pipe(); self.addCleanup(os.close,r);self.addCleanup(os.close,w)
        raw='synthetic assignment'
        m=dict(version=1,operation='listener_snapshot_spawn',request_id=str(uuid.uuid4()),payload=dict(raw_assignment=raw,assignment_sha256=hashlib.sha256(raw.encode()).hexdigest()))
        body=canonical(m)
        a.sendmsg([struct.pack('!I',len(body))],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[r,w]))]);a.sendall(body)
        got,fds=receive(b,'LISTENER')
        try:
            self.assertEqual(got,m);self.assertEqual(len(fds),2)
            os.write(fds[1],b'x');self.assertEqual(os.read(fds[0],1),b'x')
            self.assertFalse(os.get_inheritable(fds[0]))
        finally:
            for fd in fds: os.close(fd)
    def test_live_pidfd_and_accepted_peer(self):
        # This test checks primitives for this process, NOT supervisor enrollment.
        from infrastructure.t3.security.process import ProcessRecord
        if not hasattr(os,'pidfd_open'): self.skipTest('native pidfd unavailable')
        pid=os.getpid();fd=os.pidfd_open(pid);self.addCleanup(os.close,fd)
        with open(f'/proc/{pid}/stat') as f: stat=f.read()
        with open(f'/proc/{pid}/cgroup') as f: cgroup=f.read().strip()
        with open(f'/proc/{pid}/exe','rb') as f: sha=hashlib.file_digest(f,'sha256').hexdigest()
        record=ProcessRecord(pid,fd,os.getuid(),int(stat[stat.rfind(')')+2:].split()[19]),cgroup,sha)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(listener.close)
        address=self.tmp.name+'/peer'; listener.bind(address);listener.listen(1)
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(client.close);client.connect(address)
        accepted,_=listener.accept();self.addCleanup(accepted.close)
        record.authenticate(accepted)
        wrong=ProcessRecord(pid,fd,os.getuid(),record.start_ticks,cgroup,'0'*64)
        with self.assertRaises(Denied): wrong.authenticate(accepted)
    def test_spawn_has_no_pid_fallback(self):
        with self.assertRaises(Denied): spawn_verified_launcher()

if __name__=='__main__': unittest.main()
