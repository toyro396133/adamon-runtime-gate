import copy
import hashlib
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from infrastructure.t3.roles.receipts import ReceiptAuthority,ReceiptVerifier,ReceiptError,canonical,seal
from infrastructure.t3.roles.aggregation import CampaignRegistry,Aggregator

class Receipts(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate()
  props={k:{'type':'string'} for k in ('role','case','state','signer_key_id','authority_sha256','source_sha256','environment_sha256','permit_id','boot_id')}
  binding_fields=('run_id','job_id','run_attempt','host_id','session_id','dispatch_id','worker_instance_id','worker_job_guid','worker_request_id','plan_guid','listener_binary_sha256','worker_binary_sha256','launcher_binary_sha256','assignment_sha256','worker_uid','launcher_uid','worker_start_monotonic_ns','launcher_start_monotonic_ns','worker_pidfd_registry_id','launcher_pidfd_registry_id','cgroup_identity')
  props.update({k:{'type':'string'} for k in binding_fields})
  self.schema={'$defs':{'signed_private_receipt':{'type':'object','required':['payload','signature'],'additionalProperties':False,'properties':{'payload':{'type':'object','required':list(props),'additionalProperties':False,'properties':props},'signature':{'type':'string','pattern':'^[0-9a-f]{128}$'}}}}}
  self.p={'role':'AUDIT','case':'dummy','state':'AUDIT_PASS','signer_key_id':'k','authority_sha256':'a'*64,'source_sha256':'b'*64,'environment_sha256':'c'*64,'permit_id':'p','boot_id':'boot'}
  self.p.update({k:'dummy' for k in binding_fields})
  binding={k:v for k,v in self.p.items() if k not in ('state','signer_key_id','permit_id')}
  a=ReceiptAuthority('a'*64,'b'*64,'c'*64,{('AUDIT','k'):self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)},{'AUDIT':'SYNTHETIC'},canonical(self.schema),hashlib.sha256(canonical(self.schema)).hexdigest(),{'p':binding})
  self.v=ReceiptVerifier(a)
 def test_real_ed25519_acceptance(self):
  self.assertEqual(self.v.verify(seal(self.p,'AUDIT','SYNTHETIC',self.key),'AUDIT','dummy'),self.p)
 def test_tampering_and_domain(self):
  e=seal(self.p,'AUDIT','SYNTHETIC',self.key);e['payload']['state']='AUDIT_RESEARCH_FAIL'
  with self.assertRaises(ReceiptError):self.v.verify(e,'AUDIT','dummy')
  with self.assertRaises(ReceiptError):self.v.verify(seal(self.p,'AUDIT','OTHER',self.key),'AUDIT','dummy')
 def test_peer_and_source_binding(self):
  for field in ('boot_id','source_sha256','permit_id','case'):
   p=dict(self.p);p[field]='wrong'
   with self.assertRaises(ReceiptError):self.v.verify(seal(p,'AUDIT','SYNTHETIC',self.key),'AUDIT','dummy')
 def test_extra_fields_wrong_key_and_reduced_payload(self):
  for change in ('extra','missing','wrongkey'):
   p=dict(self.p)
   if change=='extra':p['command']='shell'
   elif change=='missing':p.pop('boot_id')
   else:p['signer_key_id']='untrusted'
   with self.assertRaises(ReceiptError):self.v.verify(seal(p,'AUDIT','SYNTHETIC',self.key),'AUDIT','dummy')
 def test_ascii_float_integer_rules(self):
  for v in ('\u05d0',1.0,2**53):
   with self.assertRaises(ReceiptError):canonical({'x':v})
 def test_aggregation_rejects_missing_sets_and_empty_semantics(self):
  life=tuple('case'+str(i) for i in range(27));gates=tuple('gate'+str(i) for i in range(23));micros=('micro0','micro1');controls=('control0',)
  r=CampaignRegistry(life,micros,gates,controls,{k:10 for k in life},gates[0],{m:{'life_cycles':1,'structural_direct_processings':0,'direct_batch_calls':0,'fixture_sha256':'a'*64,'schedule_sha256':'b'*64,'registry_sha256':'c'*64} for m in micros},{g:{'verified':True} for g in gates},{'control0':{'performed':True}})
  a=Aggregator(r,self.v,None)
  with self.assertRaises(ReceiptError):a.evaluate([])
  from dataclasses import replace
  with self.assertRaises(TypeError):r.gate_assertions[gates[0]]={}
  assertions=dict(r.gate_assertions);assertions[gates[0]]={}
  with self.assertRaises(ReceiptError):replace(r,gate_assertions=assertions).validate()
 def test_empty_micro_binding_rejected(self):
  life=tuple('case'+str(i) for i in range(27));gates=tuple('gate'+str(i) for i in range(23));micros=('micro0','micro1')
  r=CampaignRegistry(life,micros,gates,('control0',),{k:10 for k in life},gates[0],{m:{} for m in micros},{g:{'verified':True} for g in gates},{'control0':{'performed':True}})
  with self.assertRaises(ReceiptError):r.validate()
 def test_missing_permit_subject_rejected(self):
  from dataclasses import replace
  bindings={key:dict(value) for key,value in self.v.authority.permit_bindings.items()}
  bindings['p'].pop('case')
  self.v=ReceiptVerifier(replace(self.v.authority,permit_bindings=bindings))
  with self.assertRaises(ReceiptError):self.v.verify(seal(self.p,'AUDIT','SYNTHETIC',self.key),'AUDIT','dummy')
 def test_terminal_without_authority_rejected(self):
  r=CampaignRegistry(tuple('c'+str(i) for i in range(27)),('m0','m1'),tuple('g'+str(i) for i in range(23)),('x',),{'c'+str(i):10 for i in range(27)},'g0',{'m0':{},'m1':{}},{'g'+str(i):{'actual':True} for i in range(23)},{'x':{'actual':True}})
  with self.assertRaises(ReceiptError):Aggregator(r,self.v,None).finalize([],{},self.key,None)

if __name__=='__main__':unittest.main()
