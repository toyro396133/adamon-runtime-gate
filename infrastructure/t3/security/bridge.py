"""Protected inherited-FD bridge. Not a public enrollment endpoint."""
import array
import os
import socket
import struct
from .protocol import Denied, canonical
import json
import uuid
OPS={'listener_snapshot_spawn':2,'worker_ack':0,'authorize_assignment':0,'fixed_step_execute':0,'revoke':0}
MAX_FRAME=1024*1024

def receive(sock, role):
    """Caller must supply supervisor-created private socket, never arbitrary path."""
    sock.settimeout(30)
    data, ancillary, flags,_=sock.recvmsg(4,socket.CMSG_SPACE(2*array.array('i').itemsize),socket.MSG_WAITALL|socket.MSG_CMSG_CLOEXEC)
    fds=[]
    try:
        for level,kind,raw in ancillary:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS: raise Denied('unknown ancillary')
            values=array.array('i'); values.frombytes(raw[:len(raw)-(len(raw)%values.itemsize)])
            fds.extend(values)
        if len(data)!=4 or flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC): raise Denied('truncated bridge')
        n=struct.unpack('!I',data)[0]
        if not 0<n<=MAX_FRAME: raise Denied('frame limit')
        body=bytearray()
        while len(body)<n:
            chunk=sock.recv(n-len(body))
            if not chunk: raise Denied('bridge EOF')
            body.extend(chunk)
        def unique(pairs):
            out={}
            for k,v in pairs:
                if k in out: raise Denied('duplicate field')
                out[k]=v
            return out
        message=json.loads(bytes(body),object_pairs_hook=unique)
        canonical(message)
        if set(message)!={'version','operation','request_id','payload'} or type(message['version']) is not int or message['version']!=1 or message['operation'] not in OPS or type(message['payload']) is not dict:
            raise Denied('closed operation')
        op=message['operation']
        try: uuid.UUID(message['request_id'])
        except (ValueError,TypeError,AttributeError): raise Denied('request UUID')
        fields={'listener_snapshot_spawn':{'raw_assignment','assignment_sha256'},
                'worker_ack':{'raw_assignment','assignment_sha256'},
                'authorize_assignment':{'assignment_sha256','step_id'},
                'fixed_step_execute':{'assignment_sha256','step_id'},'revoke':{'reason'}}
        if set(message['payload'])!=fields[op]: raise Denied('payload fields')
        if op=='revoke' and message['payload']['reason'] not in {'cancel','timeout','worker_exit','renewal_failure','job_complete','bridge_failure'}: raise Denied('revoke reason')
        if op in {'listener_snapshot_spawn','worker_ack'}:
            import hashlib
            raw=message['payload']['raw_assignment']
            if type(raw) is not str or hashlib.sha256(raw.encode()).hexdigest()!=message['payload']['assignment_sha256']: raise Denied('assignment digest')
        if (role=='LISTENER' and op not in {'listener_snapshot_spawn','revoke'}) or (role=='WORKER' and op=='listener_snapshot_spawn') or role not in {'LISTENER','WORKER'}:
            raise Denied('bridge role')
        if len(fds)!=OPS[op]: raise Denied('FD count')
        for fd in fds: os.set_inheritable(fd,False)
        return message,fds
    except BaseException:
        for fd in fds: os.close(fd)
        raise

def send(sock, value):
    body=canonical(value)
    if len(body)>MAX_FRAME: raise Denied('frame limit')
    sock.sendall(struct.pack('!I',len(body))+body)

def handle(sock, role, supervisor):
    message=None;fds=[]
    try:
        message,fds=receive(sock,role)
        # A separately reviewed supervisor is mandatory. No implicit successful ack.
        if supervisor is None: raise Denied('trusted supervisor unavailable')
        result=supervisor.handle_private_message(role,message,fds)
        if hasattr(result,'wait'): result=result.wait()
        if message['operation']!='revoke':
            send(sock,{'version':1,'operation':message['operation'],'request_id':message['request_id'],'status':'COMPLETE','exit_code':result})
    except Denied:
        if supervisor is not None: supervisor.revoke('bridge_failure')
        if message is not None and message['operation']!='revoke':
            send(sock,{'version':1,'operation':message['operation'],'request_id':message['request_id'],'status':'BLOCKED','exit_code':1})
    except BaseException:
        if supervisor is not None: supervisor.revoke('bridge_failure')
        raise
    finally:
        for fd in fds: os.close(fd)
