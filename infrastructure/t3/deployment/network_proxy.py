"""Closed GitHub CONNECT broker for Listener network namespace only.

Owner opens one AF_UNIX socketpair to the restricted namespace proxy. Requests
are CONNECT only, bounded, and restricted to exact TLS hosts. No Workflow path,
command, DNS target or arbitrary URL is accepted. Worker/Launcher have no FD.
"""
import select
import socket
import threading
from ..runtime.microvm import Blocked

HOSTS=frozenset({'github.com','api.github.com','pipelines.actions.githubusercontent.com','broker.actions.githubusercontent.com','results-receiver.actions.githubusercontent.com'})
PORT=18443

class GitHubConnectBroker:
    def __init__(self,connector):
        # connector is an Owner-created TLS-egress transport, never workflow input.
        self.connector=connector;self._closed=threading.Event();self._lock=threading.RLock();self._sockets=set()
    @staticmethod
    def target(header):
        if type(header) is not bytes or len(header)>8192 or not header.endswith(b'\r\n\r\n'):raise Blocked('NETWORK_PROXY_HEADER')
        try:lines=header.decode('ascii').split('\r\n');method,target,version=lines[0].split(' ')
        except Exception as exc:raise Blocked('NETWORK_PROXY_REQUEST') from exc
        if method!='CONNECT' or version!='HTTP/1.1' or target.count(':')!=1:raise Blocked('NETWORK_PROXY_METHOD')
        host,port=target.split(':')
        if host not in HOSTS or port!='443':raise Blocked('NETWORK_PROXY_EGRESS_DENIED')
        if lines[1:]!=['Host: '+target,'','']:raise Blocked('NETWORK_PROXY_HEADERS')
        return host
    def serve(self,channel):
        with self._lock:
            if self._closed.is_set():raise Blocked('NETWORK_PROXY_CANCELLED')
            self._sockets.add(channel)
        upstream=None
        try:
            channel.settimeout(10);header=b''
            while not header.endswith(b'\r\n\r\n'):
                part=channel.recv(1)
                if not part or len(header)>=8192:raise Blocked('NETWORK_PROXY_HEADER')
                header+=part
            host=self.target(header)
            upstream=self.connector(host,443)
            with self._lock:
                if self._closed.is_set():raise Blocked('NETWORK_PROXY_CANCELLED')
                self._sockets.add(upstream)
            channel.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            while not self._closed.is_set():
                readable,_,_=select.select([channel,upstream],[],[],1)
                for src in readable:
                    data=src.recv(65536)
                    if not data:return
                    (upstream if src is channel else channel).sendall(data)
        finally:
            with self._lock:
                for sock in (channel,upstream):
                    if sock is not None:self._sockets.discard(sock);sock.close()
    def close(self):
        with self._lock:
            self._closed.set()
            for sock in tuple(self._sockets):
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                sock.close()
            self._sockets.clear()

class OwnerGitHubConnector:
    """Fixed DNS+TCP egress; broker restricts destinations before resolution.

    TLS is end-to-end Runner→GitHub; this tunnel never terminates or signs TLS.
    Owner networking must additionally constrain DNS/egress at host firewall.
    """
    def __call__(self,host,port):
        if host not in HOSTS or port!=443:raise Blocked('NETWORK_PROXY_EGRESS_DENIED')
        return socket.create_connection((host,port),timeout=10)

class NamespaceConnectBridge:
    """Owner-end SCM_RIGHTS bridge. Child sends only accepted loopback TCP FDs.

    The namespace holder binds 127.0.0.1:18443; Listener has a fixed HTTPS_PROXY
    pointing there. This object accepts no IP destination from that holder.
    """
    def __init__(self,control,broker):
        self.control=control;self.broker=broker;self._stop=threading.Event();self._threads=[]
        self.thread=threading.Thread(target=self._run,daemon=True)
    def start(self):self.thread.start();return self
    def _run(self):
        import array,os
        while not self._stop.is_set():
            try:data,anc,flags,_=self.control.recvmsg(16,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
            except OSError:return
            if not data:return
            fds=[]
            for level,kind,value in anc:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    values=array.array('i');values.frombytes(value[:len(value)//4*4]);fds.extend(values)
            if data!=b'connect' or flags&socket.MSG_CTRUNC or len(fds)!=1:
                for fd in fds:os.close(fd)
                self.broker.close();return
            channel=socket.socket(fileno=fds[0])
            if channel.family!=socket.AF_INET or channel.type!=socket.SOCK_STREAM or channel.getsockname()!=('127.0.0.1',PORT):
                channel.close();self.broker.close();return
            thread=threading.Thread(target=self._serve,args=(channel,),daemon=True)
            self._threads.append(thread);thread.start()
    def _serve(self,channel):
        try:self.broker.serve(channel)
        except (Blocked,OSError):channel.close()
    def close(self):
        self._stop.set();self.broker.close()
        try:self.control.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.thread.join(5)
        for thread in self._threads:thread.join(5)


def listener_loopback_server(control,ready=None):
    """Called only after privileged owner child unshares CLONE_NEWNET.

    No veth, TAP, forwarding or default route is installed. Only lo is brought
    up for a fixed HTTP CONNECT proxy. Guest/Worker namespaces never invoke it.
    """
    import array,fcntl,os,struct
    # Disable IPv6 before bringing loopback up; no IPv6 routes/addresses exist.
    for name in ('all','default','lo'):
        with open('/proc/sys/net/ipv6/conf/'+name+'/disable_ipv6','w') as f:f.write('1')
    ioctl_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM|socket.SOCK_CLOEXEC)
    try:
        request=struct.pack('16sH14x',b'lo',1) # IFF_UP, no external interfaces
        fcntl.ioctl(ioctl_socket.fileno(),0x8914,request) # SIOCSIFFLAGS
    finally:ioctl_socket.close()
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM|socket.SOCK_CLOEXEC)
    server.bind(('127.0.0.1',PORT));server.listen(16)
    if ready is not None:ready()
    try:
        while True:
            readable,_,_=select.select([control,server],[],[])
            if control in readable:
                if not control.recv(1):return
                raise Blocked('NETWORK_CHILD_UNEXPECTED_COMMAND')
            if server in readable:
                accepted,_=server.accept()
                try:control.sendmsg([b'connect'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[accepted.fileno()]))])
                finally:accepted.close()
    finally:server.close()
