"""Terminal AND gate over approved receipts and immutable audit manifest contents."""
from dataclasses import dataclass
from .receipts import ReceiptError,canonical,seal
import hashlib

@dataclass(frozen=True)
class CampaignRegistry:
    life: tuple
    micro: tuple
    gates: tuple
    controls: tuple
    cycle_counts: dict
    historical_gate: str
    micro_bindings: dict
    gate_assertions: dict
    control_assertions: dict
    def validate(self):
        if (len(self.life),len(self.gates),len(self.micro))!=(27,23,2):raise ReceiptError('registry cardinality')
        for group in (self.life,self.micro,self.gates,self.controls):
            if not group or len(group)!=len(set(group)):raise ReceiptError('duplicate registry')
        if set(self.cycle_counts)!=set(self.life) or set(self.micro_bindings)!=set(self.micro) or set(self.gate_assertions)!=set(self.gates) or set(self.control_assertions)!=set(self.controls):raise ReceiptError('registry coverage')
        if any(not v for v in [*self.gate_assertions.values(),*self.control_assertions.values()]):raise ReceiptError('empty semantic assertion contract')
        if self.historical_gate not in self.gates:raise ReceiptError('historical gate absent')
        import re
        fields={'registry_sha256','fixture_sha256','schedule_sha256','life_cycles','structural_direct_processings','direct_batch_calls'}
        for binding in self.micro_bindings.values():
            if type(binding) is not dict or set(binding)!=fields:raise ReceiptError('closed micro binding required')
            for name in fields:
                value=binding[name]
                if name.endswith('_sha256'):
                    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:raise ReceiptError('micro authority digest')
                elif type(value) is not int or value<0:raise ReceiptError('micro exact count')
        if any(type(v) is not int or v<=0 for v in self.cycle_counts.values()):raise ReceiptError('life exact counts')


class Aggregator:
    def __init__(self,registry,verifier,immutable_reader):
        registry.validate();self.registry=registry;self.verifier=verifier;self.reader=immutable_reader
    def _manifest(self,reference):
        import re
        if (type(reference) is not dict or set(reference)!={'object_id','version_id','sha256','size_bytes'}
            or type(reference['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',reference['sha256']) is None
            or reference['object_id']!=reference['sha256'] or type(reference['size_bytes']) is not int
            or reference['size_bytes']<0 or type(reference['version_id']) is not str
            or not reference['version_id'] or reference['version_id'] in ('null','latest')):
            raise ReceiptError('exact signed audit version required')
        data=self.reader.read_version(reference['object_id'],reference['version_id'])
        if len(data)!=reference['size_bytes'] or hashlib.sha256(data).hexdigest()!=reference['sha256']:raise ReceiptError('audit manifest bytes mismatch')
        import json
        def pairs(xs):
            result={}
            for k,v in xs:
                if k in result:raise ReceiptError('duplicate manifest key')
                result[k]=v
            return result
        try:
            result=json.loads(data,object_pairs_hook=pairs)
        except (ValueError,TypeError,UnicodeError) as exc:raise ReceiptError('invalid manifest JSON') from exc
        if type(result) is not dict:raise ReceiptError('closed manifest object required')
        return result
    def evaluate(self,receipts):
        expected={(r,s) for s in self.registry.life for r in ('LIFE','AUDIT')}|{(r,s) for s in self.registry.micro for r in ('MICRO','AUDIT')}
        accepted={};permits=set();gates={};controls={}
        for envelope in receipts:
            p=envelope.get('payload',{});identity=(p.get('role'),p.get('case',p.get('control_id')))
            if identity not in expected or identity in accepted:raise ReceiptError('unexpected/duplicate receipt')
            p=self.verifier.verify(envelope,*identity)
            if p['permit_id'] in permits:raise ReceiptError('reused permit')
            permits.add(p['permit_id']);accepted[identity]=p
            if identity[0]=='LIFE' and p['completed_cycles']!=self.registry.cycle_counts[identity[1]]:raise ReceiptError('life count mismatch')
            if identity[1] in self.registry.micro:
                if any(p.get(k)!=v for k,v in self.registry.micro_bindings[identity[1]].items()):raise ReceiptError('micro fixture/count mismatch')
            if identity[0]=='AUDIT':
                m=self._manifest(p['audit_manifest'])
                if set(m)!={'producer_receipt_sha256','gates','controls','failures','errors','skips'} or any(type(m[k]) is not int or m[k]!=0 for k in ('failures','errors','skips')):raise ReceiptError('audit coverage/failure')
                if type(m['gates']) is not dict or type(m['controls']) is not dict:raise ReceiptError('closed gate/control maps required')
                producer_role='LIFE' if identity[1] in self.registry.life else 'MICRO'
                m['_producer_identity']=(producer_role,identity[1]);p=dict(p,_manifest=m);accepted[identity]=p
                for target,results in ((gates,m['gates']),(controls,m['controls'])):
                    for name,assertions in results.items():
                        if name in target:raise ReceiptError('duplicate gate/control coverage')
                        target[name]=assertions
        if set(accepted)!=expected:raise ReceiptError('missing life/micro/audit')
        for identity,p in accepted.items():
            if identity[0]=='AUDIT':
                m=p['_manifest'];producer=accepted[m['_producer_identity']]
                if m['producer_receipt_sha256']!=hashlib.sha256(canonical(producer)).hexdigest():raise ReceiptError('audit producer mismatch')
        for actual,contracts in ((gates,self.registry.gate_assertions),(controls,self.registry.control_assertions)):
            if set(actual)!=set(contracts):raise ReceiptError('missing/unexpected gate/control')
            for name,required in contracts.items():
                if set(actual[name])!=set(required) or any(type(actual[name][key]) is not type(value) or actual[name][key]!=value for key,value in required.items()):raise ReceiptError('semantic gate/control failed')
        return {'overall_pass':True}
    def finalize(self,receipts,payload,private_key,authorization):
        raise ReceiptError('terminal execution authority not frozen; PASS_TOTAL signing disabled')
