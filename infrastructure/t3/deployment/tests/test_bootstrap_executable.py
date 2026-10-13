"""Real local OS/ELF tests. No embedded CPython build or KVM claim."""
import array
import hashlib
import os
import socket
import subprocess
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.deployment.executable_image import inspect_elf,sealed_executable,original_file
from infrastructure.t3.deployment.bootstrap_entry import receive_bootstrap,send_bootstrap
from infrastructure.t3.deployment.executable_build import build_executable,C_SOURCE
from infrastructure.t3.runtime.microvm import Blocked
from infrastructure.t3.security.protocol import Denied


def test_actual_static_elf_descriptor_execution(tmp_path):
    source=tmp_path/'smoke.c';source.write_text('int main(void){return 23;}')
    target=tmp_path/'smoke'
    completed=subprocess.run(['/usr/bin/gcc','-static','-O2',str(source),'-o',str(target)],capture_output=True)
    assert completed.returncode==0,completed.stderr
    raw=target.read_bytes();assert inspect_elf(raw)['interpreter'] is None
    fd=sealed_executable(target,hashlib.sha256(raw).hexdigest(),runtime_files={})
    try:
        pid=os.fork()
        if pid==0:
            try:os.execve(fd,['sealed-smoke'],{})
            except BaseException:os._exit(127)
        _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==23
    finally:os.close(fd)


@pytest.mark.parametrize('raw',[b'PK\x03\x04source.zip',b'#!/usr/bin/python3\nprint(1)',b'print(1)',b'\x7fELF'])
def test_source_or_truncated_image_rejected(raw):
    with pytest.raises(Blocked,match='NOT_LINUX'):inspect_elf(raw)


def test_real_dynamic_elf_loader_must_be_pinned():
    path='/usr/bin/true';raw=open(path,'rb').read()
    assert inspect_elf(raw)['interpreter']
    with pytest.raises(Blocked,match='UNPINNED'):sealed_executable(path,hashlib.sha256(raw).hexdigest(),runtime_files={})


def test_source_symlink_or_changed_digest_rejected(tmp_path):
    path=tmp_path/'source';path.write_bytes(b'abc');alias=tmp_path/'alias';alias.symlink_to(path)
    with pytest.raises(OSError):original_file(alias,hashlib.sha256(b'abc').hexdigest())
    with pytest.raises(Blocked,match='DIGEST'):original_file(path,'0'*64)


def test_missing_real_toolchain_fails_not_fake_binary(tmp_path):
    root=tmp_path/'toolchain';root.mkdir();(root/'cc').write_bytes(b'not-a-compiler')
    manifest={'version':1,'files':{'cc':hashlib.sha256(b'not-a-compiler').hexdigest()},'compiler':'cc','python_include':'include','python_library':'libpython3.12.so','runtime_files':{}}
    with pytest.raises(Blocked,match='TOOLCHAIN_MISSING'):build_executable(role='LAUNCHER',root=root,manifest=manifest,output=tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_embedded_entry_is_isolated_fixed_role_not_shell():
    assert 'PyConfig_InitIsolatedConfig' in C_SOURCE
    assert 'c.use_environment=0' in C_SOURCE and 'argc!=1' in C_SOURCE
    assert 'bootstrap_entry import main' in C_SOURCE
    assert 'system(' not in C_SOURCE and 'execv' not in C_SOURCE


def test_real_descriptor_wrong_closed_schema_rejected():
    key=Ed25519PrivateKey.generate();a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    fd=os.memfd_create('test',os.MFD_CLOEXEC)
    try:
        send_bootstrap(a,{'version':1,'role':'LAUNCHER','arbitrary_command':'sh'}, {'native':fd},key)
        with pytest.raises(Denied,match='owner'):receive_bootstrap(b,key.public_key().public_bytes_raw(),'LAUNCHER')
    finally:os.close(fd);a.close();b.close()


def test_stream_bootstrap_is_not_silently_accepted():
    a,b=socket.socketpair()
    try:
        with pytest.raises(Denied,match='seqpacket'):send_bootstrap(a,{}, {},Ed25519PrivateKey.generate())
    finally:a.close();b.close()


def test_real_dynamic_dependency_names_are_parsed():
    info=inspect_elf(open('/usr/bin/true','rb').read())
    assert 'libc.so.6' in info['needed']


def test_private_broker_positive_original_and_seal_actual_socket():
    import threading
    from infrastructure.t3.deployment.bootstrap_entry import BrokerCapabilities,OwnerBrokerServer
    from infrastructure.t3.deployment.nonresearch_images import SUBJECT
    class RetainedSyntheticRecord:
        def verify(self):pass
    class ExistingScopeShape:
        def __init__(self):self.originals=[];self.partials=[]
        def revoke(self):return None
        def revoke_all(self):return None
        def preserve_partial(self,reason):self.partials.append(reason);return None
        def preserve_authenticated_original(self,raw,completion):self.originals.append(raw);return None
        def seal_complete(self):return {'scope':'SYNTHETIC_LOCAL_CANARY_ONLY','sealed':True}
    a,b=socket.socketpair();scope=ExistingScopeShape()
    from infrastructure.t3.runtime.guest import BINDING
    binding={k:'a'*(40 if k=='workflow_sha' else 64) for k in BINDING}
    from infrastructure.t3.deployment.nonresearch_images import SUBJECT,SOURCE,FIXTURE
    binding.update(job_id=1,run_id=2,run_attempt=1,role='LIFE',subject=SUBJECT,source_sha256=hashlib.sha256(SOURCE).hexdigest(),fixture_sha256=hashlib.sha256(FIXTURE).hexdigest())
    server=OwnerBrokerServer(a,binding=binding,role='LAUNCHER',record=RetainedSyntheticRecord(),credential_scope=scope,evidence_scope=scope)
    client=BrokerCapabilities(b.fileno());errors=[]
    def serve():
        try:
            assert server.serve_once()=='evidence.original'
            assert server.serve_once()=='evidence.seal'
        except BaseException as exc:errors.append(exc)
    thread=threading.Thread(target=serve);thread.start()
    try:
        raw=b'original-canary-bytes'
        completion={'status':'COMPLETE','binding':binding,'artifacts':[{'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)}]}
        client.preserve_authenticated_original(raw,completion)
        assert client.seal_complete()['sealed'] is True
        thread.join(2);assert not thread.is_alive() and not errors
        assert scope.originals==[raw]
    finally:client.channel.close();a.close();b.close()


def test_private_broker_rejects_overall_pass_or_command_before_backend():
    import struct
    from infrastructure.t3.deployment.bootstrap_entry import OwnerBrokerServer
    from infrastructure.t3.security.protocol import canonical
    class Scope:
        def verify(self):pass
        def revoke(self):raise AssertionError('unexpected backend')
        revoke_all=preserve_partial=preserve_authenticated_original=seal_complete=revoke
    a,b=socket.socketpair();scope=Scope()
    from infrastructure.t3.runtime.guest import BINDING
    binding={k:'a'*(40 if k=='workflow_sha' else 64) for k in BINDING}
    from infrastructure.t3.deployment.nonresearch_images import SUBJECT,SOURCE,FIXTURE
    binding.update(job_id=1,run_id=2,run_attempt=1,role='LIFE',subject=SUBJECT,source_sha256=hashlib.sha256(SOURCE).hexdigest(),fixture_sha256=hashlib.sha256(FIXTURE).hexdigest())
    server=OwnerBrokerServer(a,binding=binding,role='LAUNCHER',record=scope,credential_scope=scope,evidence_scope=scope)
    try:
        raw=canonical({'operation':'aggregate.finalize','argument':None})
        b.sendall(struct.pack('!I',len(raw))+raw)
        with pytest.raises(Denied,match='role mismatch'):server.serve_once()
    finally:a.close();b.close()


def test_adoption_denies_current_host_namespace_and_invalid_owner():
    from infrastructure.t3.deployment.network import OwnerNetworkScope
    from infrastructure.t3.deployment.tests.test_network import policy
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    net=os.open('/proc/self/ns/net',os.O_RDONLY)
    pidfd=os.pidfd_open(os.getpid())
    try:
        with pytest.raises(Blocked,match='OWNER_UID|HOLDER_IDENTITY'):
            OwnerNetworkScope.adopt(policy(),'a'*64,holder_pid=os.getpid(),holder_pidfd=pidfd,control_fd=a.fileno(),namespace_fd=net)
        # Rejection never kills the caller or steals caller-owned descriptors.
        for fd in (pidfd,a.fileno(),net):os.fstat(fd)
    finally:os.close(pidfd);os.close(net);a.close();b.close()


def test_adoption_resource_copies_have_one_cleanup_owner(monkeypatch):
    """Static kernel-validation double with real sockets/pidfd; not netns proof."""
    import threading
    from infrastructure.t3.deployment.network import OwnerNetworkScope
    from infrastructure.t3.deployment.tests.test_network import policy
    from pathlib import Path
    real_socket=socket.socket
    class PeerSocket:
        def __init__(self,fileno):self.inner=real_socket(fileno=fileno);self.family=self.inner.family;self.type=self.inner.type
        def getsockopt(self,*args):return __import__('struct').pack('3i',11,0,0)
        def close(self):self.inner.close()
    import infrastructure.t3.deployment.network as module
    real_open=open
    def synthetic_proc(path,*args,**kwargs):
        import io
        if str(path).startswith('/proc/self/fdinfo/'):
            return io.StringIO('Pid:\t12345\n')
        if str(path)=='/proc/12345/status':return io.StringIO('Uid:\t0\t0\t0\t0\n')
        return real_open(path,*args,**kwargs)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    pidfd=os.pidfd_open(os.getpid());net=os.open('/proc/self/ns/net',os.O_RDONLY)
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    monkeypatch.setattr(module.socket,'socket',PeerSocket)
    monkeypatch.setattr(module,'open',synthetic_proc,raising=False)
    monkeypatch.setattr(module.LinuxNamespaceBackend,'validate',lambda *args:None)
    closed=[]
    def synthetic_close(self,pid,pfd,channel,nfd):
        closed.append(pid);channel.close();os.close(pfd);os.close(nfd)
    monkeypatch.setattr(module.LinuxNamespaceBackend,'close',synthetic_close)
    try:
        scope=OwnerNetworkScope.adopt(policy(),'a'*64,holder_pid=12345,holder_pidfd=pidfd,control_fd=a.fileno(),namespace_fd=net)
        assert scope._resource[1]!=pidfd and scope._resource[3]!=net
        threads=[threading.Thread(target=scope.close) for _ in range(4)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        assert closed==[12345]
        for fd in (pidfd,a.fileno(),net):os.fstat(fd)
    finally:os.close(pidfd);os.close(net);a.close();b.close()
