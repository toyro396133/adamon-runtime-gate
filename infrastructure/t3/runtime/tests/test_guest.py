"""Real Ed25519/local framing; synthetic adapters, no guest or research run."""
import socket
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from infrastructure.t3.runtime.guest import *


def binding():
    return dict(job_id=1,run_id=2,run_attempt=1,workflow_sha='a'*40,
                assignment_sha256='a'*64,launcher_spki_sha256='b'*64,
                permit_sha256='c'*64,role='MICRO',subject='fixed',
                source_sha256='d'*64,fixture_sha256='e'*64)


class Tests(unittest.TestCase):
    def test_signed_exact_completion(self):
        a,b=socket.socketpair(); key=Ed25519PrivateKey.generate(); errors=[]
        def guest():
            try:
                serve_guest(b,binding(),{('MICRO','fixed'):lambda:[dict(object_id='1'*64,version_id='version',sha256='f'*64,size_bytes=10)]},lambda att,bind:att=='signed-capability',key)
            except BaseException as e: errors.append(e)
        thread=threading.Thread(target=guest); thread.start()
        try:
            client=GuestClient(a,binding(),key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
            client.execute('signed-capability')
            result=client.poll_completion(1)
            self.assertEqual(result['binding'],binding()); self.assertEqual(errors,[])
            with self.assertRaises(Blocked): client.execute('signed-capability')
        finally: thread.join(2); a.close(); b.close()

    def rejected(self, mutate=None, registered=True, permitted=True):
        a,b=socket.socketpair(); key=Ed25519PrivateKey.generate()
        request=dict(version=4,operation='fixed-role-execute',binding=binding(),launch_attestation='x')
        if mutate: mutate(request)
        send(a,request)
        try:
            with self.assertRaises(Blocked):
                serve_guest(b,binding(),{('MICRO','fixed'):lambda:[]} if registered else {},lambda att,bind:permitted,key)
        finally: a.close(); b.close()
    def test_wrong_permit(self): self.rejected(permitted=False)
    def test_unregistered_subject(self): self.rejected(registered=False)
    def test_wrong_role(self): self.rejected(lambda r:r['binding'].update(role='AUDIT'))
    def test_command_rejected(self): self.rejected(lambda r:r.update(command='anything'))
    def test_truncated_frame(self):
        a,b=socket.socketpair(); a.sendall(struct.pack('!I',10)+b'{'); a.close()
        try:
            with self.assertRaises(Blocked): receive(b)
        finally: b.close()
    def test_bad_signature(self):
        a,b=socket.socketpair(); key=Ed25519PrivateKey.generate()
        try:
            client=GuestClient(a,binding(),key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
            client.request_sha256='a'*64
            payload=dict(version=4,status='COMPLETE',request_sha256='a'*64,binding=binding(),artifacts=[dict(object_id='1'*64,version_id='v',sha256='a'*64,size_bytes=1)])
            send(b,dict(payload=payload,signature_hex='00'*64))
            with self.assertRaisesRegex(Blocked,'SIGNATURE'): client.poll_completion(1)
        finally: a.close(); b.close()
    def test_signed_guest_cannot_supply_unregistered_artifact_refs(self):
        good=dict(object_id='1'*64,version_id='v1',sha256='a'*64,size_bytes=1)
        cases=[
            [dict(good,object_id='short')],
            [dict(good,object_id='../path')],
            [good,dict(good)],
            [dict(good,version_id='latest')],
            [dict(good,version_id='null')],
            [dict(good,version_id='../'+'x'*256)],
            [dict(good,version_id='not valid')],
            [dict(good,size_bytes=0)],
            [dict(good,size_bytes=True)],
            [dict(good,sha256='A'*64)],
        ]
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                a,b=socket.socketpair()
                key=Ed25519PrivateKey.generate()
                try:
                    client=GuestClient(a,binding(),key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
                    client.request_sha256='a'*64
                    payload=dict(version=4,status='COMPLETE',request_sha256='a'*64,
                                 binding=binding(),artifacts=artifacts)
                    envelope=dict(payload=payload,signature_hex=key.sign(DOMAIN+canonical(payload)).hex())
                    send(b,envelope)
                    with self.assertRaises(Blocked): client.poll_completion(1)
                finally:
                    a.close(); b.close()

    def test_partial_frame_timeout_keeps_bytes(self):
        a,b=socket.socketpair(); key=Ed25519PrivateKey.generate()
        try:
            client=GuestClient(a,binding(),key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
            client.request_sha256='a'*64
            payload=dict(version=4,status='COMPLETE',request_sha256='a'*64,binding=binding(),artifacts=[dict(object_id='1'*64,version_id='v',sha256='a'*64,size_bytes=1)])
            envelope=dict(payload=payload,signature_hex=key.sign(DOMAIN+canonical(payload)).hex())
            body=canonical(envelope); frame=struct.pack('!I',len(body))+body
            b.sendall(frame[:20]); self.assertIsNone(client.poll_completion(.01))
            b.sendall(frame[20:]); self.assertEqual(client.poll_completion(1),payload)
        finally: a.close(); b.close()


if __name__=='__main__': unittest.main()
