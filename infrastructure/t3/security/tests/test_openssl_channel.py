"""Real synthetic TLS test; optional reviewed backend required, no research."""
import datetime, hashlib, os, socket, tempfile, threading, unittest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from infrastructure.t3.security.protocol import spki_digest,Denied
from infrastructure.t3.security.openssl_channel import server_context,accept,verify_bound_leaf
from infrastructure.t3.security.process import ProcessRecord
try:
    from OpenSSL import SSL,crypto
except ImportError:
    SSL=None

@unittest.skipIf(SSL is None,'pyOpenSSL backend not installed; TLS runtime unverified')
class RealTLS(unittest.TestCase):
    def test_real_unix_mtls_critical_binding_and_exporter(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        ca_key=Ed25519PrivateKey.generate();server_key=Ed25519PrivateKey.generate();client_key=Ed25519PrivateKey.generate()
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic')])
        oid=ObjectIdentifier('1.3.6.1.4.1.55555.4.1'); binding=b'synthetic bound process'
        def make(key,serial,ca=False,client=False):
            b=x509.CertificateBuilder().subject_name(name if ca else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'client' if client else 'server')])).issuer_name(name).public_key(key.public_key()).serial_number(serial).not_valid_before(now-datetime.timedelta(seconds=5)).not_valid_after(now+datetime.timedelta(minutes=5)).add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),critical=True).add_extension(x509.KeyUsage(True,False,False,False,False,ca,ca,False,False),critical=True)
            if not ca:b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            if client:b=b.add_extension(x509.UnrecognizedExtension(oid,binding),critical=True)
            return b.sign(ca_key,None)
        ca=make(ca_key,1,True);server=make(server_key,2);client=make(client_key,3,client=True)
        expected=spki_digest(client_key.public_key())
        ctx=server_context(server,server_key,ca,oid,binding,expected)
        cctx=SSL.Context(SSL.TLS_CLIENT_METHOD);cctx.set_min_proto_version(SSL.TLS1_3_VERSION);cctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        cctx.use_certificate(client);cctx.use_privatekey(client_key);cctx.get_cert_store().add_cert(crypto.X509.from_cryptography(ca));cctx.set_verify(SSL.VERIFY_PEER,lambda c,x,e,d,ok:ok)
        pid=os.getpid();pidfd=os.pidfd_open(pid)
        with open(f'/proc/{pid}/stat') as f: stat=f.read()
        with open(f'/proc/{pid}/cgroup') as f: cg=f.read().strip()
        with open(f'/proc/{pid}/exe','rb') as f: sha=hashlib.file_digest(f,'sha256').hexdigest()
        record=ProcessRecord(pid,pidfd,os.getuid(),int(stat[stat.rfind(')')+2:].split()[19]),cg,sha)
        result=[];errors=[]
        with tempfile.TemporaryDirectory() as tmp:
            listen=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listen.bind(tmp+'/tls');listen.listen(1)
            def run():
                raw,_=listen.accept();raw.setblocking(True)
                try:
                    conn,key,export=accept(ctx,raw,record,ca,oid,binding,expected)
                    result.append(export);conn.send(b'ok');conn.close()
                except Exception as e:errors.append(e)
                finally:raw.close()
            t=threading.Thread(target=run);t.start()
            raw=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);raw.connect(tmp+'/tls')
            conn=SSL.Connection(cctx,raw);conn.set_connect_state();conn.do_handshake()
            client_export=hashlib.sha256(conn.export_keying_material(b'ADAMON-P4V3-CHANNEL',32,None)).hexdigest()
            self.assertEqual(conn.recv(2),b'ok');conn.close();raw.close();t.join(6);listen.close()
        os.close(pidfd)
        self.assertFalse(t.is_alive());self.assertFalse(errors,errors);self.assertEqual(result,[client_export])
        with self.assertRaises(Denied):verify_bound_leaf(client,ca,oid,b'wrong',expected)
        with self.assertRaises(Denied):verify_bound_leaf(client,ca,oid,binding,'0'*64)
