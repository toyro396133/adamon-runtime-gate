"""Actual CA/native sealed-key/SCM_RIGHTS bootstrap to separate process.
No guard/UID isolation/KVM/Actions attestation is implied.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID, ObjectIdentifier
from infrastructure.t3.security.native import Native
from infrastructure.t3.security.supervisor import BootstrapCA, deliver_launcher_bootstrap
from infrastructure.t3.integration_tests.test_connected_supervisor import record

CHILD = '''
import json,os,socket,sys
from cryptography.x509.oid import ObjectIdentifier
from infrastructure.t3.runtime.launcher import receive_bootstrap
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1])
spki=os.read(int(sys.argv[2]),64).decode();os.close(int(sys.argv[2]))
fd,cert=receive_bootstrap(s,spki,json.loads(sys.argv[3]),bytes.fromhex(sys.argv[4]),ObjectIdentifier(sys.argv[5]))
assert os.fstat(fd).st_size==32
os.close(fd);s.close();print('BOOTSTRAP_VERIFIED')
'''


def test_supervisor_to_launcher_real_framed_bootstrap(tmp_path):
    source=Path(__file__).resolve().parents[1]/'security/native_supervisor.c'
    library=tmp_path/'lib.so'
    subprocess.run(['gcc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-o',str(library)],check=True,capture_output=True)
    native=Native(str(library),hashlib.sha256(library.read_bytes()).hexdigest())
    ca_key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'NONRESEARCH-TEST-CA')])
    ca_cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(seconds=30))
        .not_valid_after(now+timedelta(minutes=5)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,None))
    oid=ObjectIdentifier('1.3.6.1.4.1.57264.1.1');binding={'test':'NONRESEARCH_BOOTSTRAP_ONLY','job_id':1}
    issuer=BootstrapCA(ca_cert,ca_key,native,oid)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);path=tmp_path/'bootstrap.sock'
    listener.bind(str(path));listener.listen(1);listener.settimeout(5)
    rd,wr=os.pipe()
    child=subprocess.Popen([sys.executable,'-c',CHILD,str(path),str(rd),json.dumps(binding),ca_key.public_key().public_bytes_raw().hex(),oid.dotted_string],
        pass_fds=(rd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    os.close(rd);pidfd=os.pidfd_open(child.pid);connection=None
    try:
        connection,_=listener.accept()
        spki=deliver_launcher_bootstrap(issuer,record(child.pid,pidfd),binding,connection)
        assert os.write(wr,spki.encode())==64
        os.close(wr);wr=-1
        stdout,stderr=child.communicate(timeout=5)
        assert child.returncode==0,stderr
        assert stdout.strip()=='BOOTSTRAP_VERIFIED'
    finally:
        if child.poll() is None:child.kill();child.wait()
        if connection is not None:connection.close()
        listener.close();os.close(pidfd)
        if wr>=0:os.close(wr)
