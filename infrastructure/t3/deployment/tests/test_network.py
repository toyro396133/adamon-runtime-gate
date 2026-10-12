import copy
import hashlib
import os
import socket
import threading
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from infrastructure.t3.deployment.network import NetworkPolicy,DOMAIN,CHANNELS,OwnerNetworkScope,LinuxNamespaceBackend
from infrastructure.t3.deployment.network_proxy import GitHubConnectBroker
from infrastructure.t3.runtime.guest import canonical
from infrastructure.t3.runtime.microvm import Blocked

def policy():
    key=Ed25519PrivateKey.generate();p={'version':1,'job_binding_sha256':'a'*64,'channels':copy.deepcopy(CHANNELS),'network':'NO_INTERFACES_NO_ROUTES_LOOPBACK_DOWN','expires_at':100}
    env={'payload':p,'signature_hex':key.sign(DOMAIN+canonical(p)).hex()}
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return NetworkPolicy.verify(env,pub,lambda:1)

class KernelDouble:
    """Explicit synthetic adapter; not a privileged namespace test."""
    def __init__(self,fail=False):self.fail=fail;self.closed=0;self.started=0
    def create(self):self.started+=1;return (1,2,3,4)
    def validate(self,*_):
        if self.fail:raise Blocked('NETWORK_UNAUTHORIZED_ROUTE')
    def close(self,*_):self.closed+=1

def test_signed_policy_and_binding():
    p=policy();p.require('a'*64)
    with pytest.raises(Blocked,match='BINDING'):p.require('b'*64)

def test_start_rollback_and_cancel_idempotence():
    b=KernelDouble(True);scope=OwnerNetworkScope(policy(),'a'*64,b)
    with pytest.raises(Blocked,match='ROUTE'):scope.start()
    assert b.closed==1
    scope.close();scope.close()
    with pytest.raises(Blocked,match='STATE'):scope.start()

def test_real_fd_lifecycle_without_kernel_privilege():
    left,right=socket.socketpair();fd=os.dup(left.fileno())
    os.set_inheritable(fd,False);assert not os.get_inheritable(fd)
    os.close(fd);left.close();right.close()
    with pytest.raises(OSError):os.fstat(fd)

def test_concurrent_cancellation():
    b=KernelDouble();scope=OwnerNetworkScope(policy(),'a'*64,b).start()
    threads=[threading.Thread(target=scope.close) for _ in range(8)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert b.closed==1

@pytest.mark.parametrize('wire_request',[b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n',b'CONNECT github.com:80 HTTP/1.1\r\nHost: github.com:80\r\n\r\n',b'GET https://github.com/ HTTP/1.1\r\nHost: github.com\r\n\r\n',b'CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nAuthorization: x\r\n\r\n'])
def test_proxy_negative_egress(wire_request):
    with pytest.raises(Blocked):GitHubConnectBroker.target(wire_request)

def test_real_socket_proxy_positive_and_cleanup():
    a,b=socket.socketpair();c,d=socket.socketpair();calls=[]
    def connect(host,port):calls.append((host,port));return c
    broker=GitHubConnectBroker(connect)
    thread=threading.Thread(target=broker.serve,args=(b,));thread.start()
    a.sendall(b'CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n')
    assert a.recv(100).startswith(b'HTTP/1.1 200')
    a.sendall(b'opaque TLS');assert d.recv(100)==b'opaque TLS'
    d.sendall(b'response');assert a.recv(100)==b'response'
    a.close();thread.join(3);assert not thread.is_alive()
    broker.close();d.close();assert calls==[('github.com',443)]

def test_channel_role_and_kernel_peer_identity():
    from infrastructure.t3.deployment.network import OwnerChannel
    a,b=socket.socketpair()
    try:
        cap=OwnerChannel(a.fileno(),'WORKER','assignment',os.getuid())
        assert cap.verify(policy(),'a'*64) is cap
        assert not os.get_inheritable(a.fileno())
        with pytest.raises(Blocked,match='ROLE'):OwnerChannel(a.fileno(),'WORKER','evidence',os.getuid()).verify(policy(),'a'*64)
        with pytest.raises(Blocked,match='PEER'):OwnerChannel(a.fileno(),'WORKER','assignment',os.getuid()+1).verify(policy(),'a'*64)
    finally:a.close();b.close()
