"""Accepted receipt schema is privately injected and pinned; no research IDs here."""
from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

class ReceiptError(ValueError): pass

def canonical(value):
    def check(v):
        if isinstance(v,str) and not v.isascii(): raise ReceiptError('ASCII required')
        if isinstance(v,float): raise ReceiptError('floats forbidden')
        if isinstance(v,int) and not isinstance(v,bool) and abs(v)>2**53-1: raise ReceiptError('integer range')
        if isinstance(v,Mapping):
            for k,x in v.items():
                if not isinstance(k,str):raise ReceiptError('string key required')
                check(k);check(x)
        elif isinstance(v,(tuple,list)):
            for x in v:check(x)
        elif v is not None and not isinstance(v,(str,int,bool)):raise ReceiptError('unsupported type')
    check(value)
    def plain(v):
        if isinstance(v,Mapping):return {k:plain(x) for k,x in v.items()}
        if isinstance(v,(tuple,list)):return [plain(x) for x in v]
        return v
    return json.dumps(plain(value),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

@dataclass(frozen=True)
class ReceiptAuthority:
    authority_sha256: str
    source_sha256: str
    environment_sha256: str
    keys: dict
    domains: dict
    schema: bytes
    schema_sha256: str
    # Mapping immutable permit IDs to the exact private live-issued job bindings.
    permit_bindings: dict

    def __post_init__(self):
        from .immutable import freeze
        for name in ("keys", "domains", "permit_bindings"):
            object.__setattr__(self,name,freeze(getattr(self,name)))

class ReceiptVerifier:
    def __init__(self,authority):
        self.authority=authority
        if not isinstance(authority.schema,bytes) or hashlib.sha256(authority.schema).hexdigest()!=authority.schema_sha256:
            raise ReceiptError('receipt schema pin mismatch')
        schema=json.loads(authority.schema)
        self.validator=Draft202012Validator({'$ref':'#/$defs/signed_private_receipt','$defs':schema['$defs']})
    def verify(self,envelope,role,subject=None):
        try:self.validator.validate(envelope)
        except Exception as exc:raise ReceiptError('accepted schema violation') from exc
        payload=envelope['payload'];canonical(payload)
        if payload['role']!=role:raise ReceiptError('role mismatch')
        actual=payload.get('case',payload.get('control_id','CAMPAIGN'))
        if subject is not None and actual!=subject:raise ReceiptError('subject mismatch')
        for key in ('authority_sha256','source_sha256','environment_sha256'):
            if payload[key]!=getattr(self.authority,key):raise ReceiptError('authority mismatch')
        binding=self.authority.permit_bindings.get(payload['permit_id'])
        required={'role','authority_sha256','source_sha256','environment_sha256','run_id','job_id','run_attempt','host_id','session_id','boot_id','dispatch_id','worker_instance_id','worker_job_guid','worker_request_id','plan_guid','listener_binary_sha256','worker_binary_sha256','launcher_binary_sha256','assignment_sha256','worker_uid','launcher_uid','worker_start_monotonic_ns','launcher_start_monotonic_ns','worker_pidfd_registry_id','launcher_pidfd_registry_id','cgroup_identity'}
        if not binding or not required<=binding.keys() or any((not isinstance(payload.get(k),Mapping) or canonical(payload[k])!=canonical(v)) if isinstance(v,Mapping) else (type(payload.get(k)) is not type(v) or payload.get(k)!=v) for k,v in binding.items()):raise ReceiptError('unbound permit/job/launcher')
        if binding.get('role')!=role:raise ReceiptError('permit role mismatch')
        subject_field='case' if 'case' in payload else 'control_id' if 'control_id' in payload else None
        if subject_field is not None and (subject_field not in binding or binding[subject_field]!=actual):
            raise ReceiptError('permit subject missing/mismatch')

        key=self.authority.keys.get((role,payload['signer_key_id']))
        if key is None:raise ReceiptError('untrusted role signer')
        try:Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(envelope['signature']),self.authority.domains[role].encode()+b'\n'+canonical(payload))
        except Exception as exc:raise ReceiptError('invalid signature') from exc
        complete={'LIFE':'SEALED_COMPLETE','MICRO':'SEALED_COMPLETE','AUDIT':'AUDIT_PASS','AGGREGATION':'PASS_TOTAL'}
        if payload['state']!=complete[role]:raise ReceiptError('incomplete/failed receipt')
        return payload

def seal(payload,role,domain,private_key):
    if payload['role']!=role:raise ReceiptError('signer role mismatch')
    return {'payload':payload,'signature':private_key.sign(domain.encode()+b'\n'+canonical(payload)).hex()}
