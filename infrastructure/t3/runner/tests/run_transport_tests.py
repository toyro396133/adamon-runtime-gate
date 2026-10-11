"""Real Linux FD/SCM_RIGHTS tests for compiled bridge; upstream types are test doubles."""
import argparse,array,hashlib,json,os,pathlib,socket,struct,subprocess,threading,unittest,uuid
DOTNET=HARNESS=None
class TransportTests(unittest.TestCase):
    def exchange(self, mode='good', rights=False):
        parent,child=socket.socketpair(); raw='{}'; request={'version':1,'operation':'listener_snapshot_spawn' if rights else 'worker_ack','request_id':str(uuid.uuid4()),'payload':{'raw_assignment':raw,'assignment_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
        pipes=[]
        if rights:
            for _ in range(2):
                read,write=os.pipe();os.close(write);pipes.append(read)
        args=[DOTNET,HARNESS,str(child.fileno()),json.dumps(request)]+list(map(str,pipes))
        process=subprocess.Popen(args,pass_fds=(child.fileno(),*pipes),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        child.close()
        descriptors=[]
        try:
            parent.settimeout(5)
            head,anc,flags,_=parent.recvmsg(4,socket.CMSG_SPACE(8),socket.MSG_WAITALL)
            self.assertEqual(len(head),4); size=struct.unpack('!I',head)[0];body=b''
            while len(body)<size:body+=parent.recv(size-len(body))
            self.assertEqual(json.loads(body),request)
            for level,kind,bytes_ in anc:
                self.assertEqual((level,kind),(socket.SOL_SOCKET,socket.SCM_RIGHTS)); values=array.array('i');values.frombytes(bytes_);descriptors.extend(values)
            self.assertEqual(len(descriptors),2 if rights else 0)
            response={'version':1,'operation':request['operation'],'request_id':request['request_id'],'status':'COMPLETE','exit_code':0}
            if mode=='wrong_id':response['request_id']=str(uuid.uuid4())
            if mode=='boolean_version':response['version']=True
            if mode=='blocked':response['status']='BLOCKED'
            encoded=json.dumps(response).encode()
            if mode=='duplicate':encoded=encoded[:-1]+b',"version":1}'
            parent.sendall(struct.pack('!I',len(encoded))+encoded)
            stdout,stderr=process.communicate(timeout=5)
            return process.returncode,stdout,stderr
        finally:
            parent.close()
            for fd in pipes+descriptors:os.close(fd)
            if process.poll() is None:process.kill();process.wait()
    def test_real_socket_framing(self):self.assertEqual(self.exchange()[0],0)
    def test_real_scm_rights(self):self.assertEqual(self.exchange(rights=True)[0],0)
    def test_response_wrong_binding(self):self.assertNotEqual(self.exchange('wrong_id')[0],0)
    def test_response_boolean_version(self):self.assertNotEqual(self.exchange('boolean_version')[0],0)
    def test_response_duplicate_field(self):self.assertNotEqual(self.exchange('duplicate')[0],0)
    def test_supervisor_denial(self):self.assertNotEqual(self.exchange('blocked')[0],0)
    def test_no_private_descriptor(self):
        request={'version':1,'operation':'worker_ack','request_id':str(uuid.uuid4()),'payload':{}}
        p=subprocess.run([DOTNET,HARNESS,'199',json.dumps(request)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(p.returncode,0);self.assertIn('P4_PRIVATE_STREAM_REQUIRED',p.stderr)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('dotnet');parser.add_argument('harness');options=parser.parse_args();DOTNET=options.dotnet;HARNESS=options.harness
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests))
    raise SystemExit(0 if result.wasSuccessful() else 1)
