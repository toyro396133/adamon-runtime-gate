"""Subordinate operation provenance inside existing signed immutable inventories.

No research names, evaluator truth, permit issuance or terminal signing. The
privileged factory injects exact operation specs and the existing role identity.
"""
import json
import sqlite3
from dataclasses import dataclass
from types import MappingProxyType
from .evidence import StorageFailure,canonical,sha,HEX
from .chain import InventoryProducer,SignedInventoryReader

DOMAIN=b'ADAMON-T3-OPERATION-PROVENANCE-V1\0'
RECEIPT='operation_receipt'


def binding(payload):
    # inventory digest cannot recursively bind itself. Everything else in the
    # already-verified producer receipt, including full Job/permit, is retained.
    return {k:v for k,v in payload.items() if k not in ('inventory_sha256','state')}


@dataclass(frozen=True)
class OperationSpec:
    source_sha256:str
    labels:frozenset
    def __post_init__(self):
        if type(self.source_sha256) is not str or not HEX.fullmatch(self.source_sha256):raise StorageFailure('operation source pin')
        object.__setattr__(self,'labels',frozenset(self.labels))
        if not self.labels or RECEIPT in self.labels or any(type(v) is not str or not v for v in self.labels):raise StorageFailure('closed operation labels')


class OperationProducer:
    def __init__(self,*,inventory_producer,specs,producer_identity,signer,ledger):
        if not isinstance(inventory_producer,InventoryProducer):raise StorageFailure('existing inventory producer required')
        # Repeated byte-identical controls also occur on real S3. Persist only
        # signed exact-version receipts, with fresh version readback on reuse.
        from .s3_protected import ProtectedS3EvidenceWriter
        if isinstance(inventory_producer.store,ProtectedS3EvidenceWriter):
            from .s3 import S3EvidenceReader
            from .journal import JournaledS3Store
            writer=inventory_producer.store
            authority,attempt,_=writer.prefix.split('/')
            reader=S3EvidenceReader(writer.client,bucket=writer.bucket,authority_sha256=authority,attempt_id=attempt,
                trusted_key=writer.signer.public_key(),trusted_key_id=writer.key_id,kms_key_arn=writer.kms)
            inventory_producer.store=JournaledS3Store(writer,reader,ledger=str(ledger)+'.members')
        if type(specs) is not dict or not specs or any(not isinstance(v,OperationSpec) for v in specs.values()):raise StorageFailure('closed operation registry')
        self.producer=inventory_producer;self.specs=MappingProxyType(dict(specs));self.identity=json.loads(canonical(binding(producer_identity)))
        self.signer=signer;self.ledger=ledger
        with self.connect() as c:c.execute('CREATE TABLE IF NOT EXISTS operation_publications(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, inventory BLOB NOT NULL)')
    def connect(self):return sqlite3.connect(self.ledger,timeout=15)
    def capture(self,operation_id,operation,artifacts,*,state='SEALED_COMPLETE'):
        if type(operation_id) is not str or not operation_id or len(operation_id)>128:raise StorageFailure('operation identity')
        spec=self.specs.get(operation)
        if spec is None or type(artifacts) is not dict or set(artifacts)!=spec.labels or any(type(v) is not bytes for v in artifacts.values()):raise StorageFailure('operation source/member contract')
        if state not in ('SEALED_COMPLETE','SEALED_PARTIAL'):raise StorageFailure('operation state')
        if self.producer.labels!=spec.labels|{RECEIPT}:raise StorageFailure('operation producer label mismatch')
        payload={'version':1,'operation_id':operation_id,'operation':operation,'source_sha256':spec.source_sha256,'binding':self.identity,'state':state,'members':{k:{'sha256':sha(v),'size_bytes':len(v)} for k,v in artifacts.items()}}
        fingerprint=sha(canonical(payload))
        ledger_id=sha(canonical(self.identity))+':'+operation_id
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT fingerprint,inventory FROM operation_publications WHERE id=?',(ledger_id,)).fetchone()
            if row:
                if row[0]!=fingerprint:raise StorageFailure('operation replay/substitution/PARTIAL upgrade')
                return json.loads(row[1])
            envelope={'payload':payload,'signature':self.signer.sign(DOMAIN+canonical(payload)).hex()}
            inventory=self.producer.seal({**artifacts,RECEIPT:canonical(envelope)},state=state)
            c.execute('INSERT INTO operation_publications VALUES(?,?,?)',(ledger_id,fingerprint,canonical(inventory)))
            return inventory


class OperationReader:
    def __init__(self,*,producer_receipt,inventory,receipt_verifier,reader_factory,specs,operation_key):
        payload=producer_receipt.get('payload',{})
        role=payload.get('role');subject=payload.get('case',payload.get('control_id'))
        if role not in ('LIFE','MICRO'):raise StorageFailure('operation producer role')
        verified=receipt_verifier.verify(producer_receipt,role,subject)
        expected_key=receipt_verifier.authority.keys.get((role,verified['signer_key_id']))
        if expected_key!=operation_key.public_bytes_raw():raise StorageFailure('operation key not producer role signer')
        reader=reader_factory(verified,inventory)
        if not isinstance(reader,SignedInventoryReader):raise StorageFailure('concrete signed inventory reader required')
        raw=reader.read_member(RECEIPT)
        def unique(pairs):
            value={}
            for k,v in pairs:
                if k in value:raise StorageFailure('duplicate operation JSON key')
                value[k]=v
            return value
        try:envelope=json.loads(raw,object_pairs_hook=unique)
        except (ValueError,UnicodeError) as exc:raise StorageFailure('operation JSON') from exc
        if type(envelope) is not dict or set(envelope)!={'payload','signature'}:raise StorageFailure('operation envelope')
        p=envelope['payload']
        if type(p) is not dict or set(p)!={'version','operation_id','operation','source_sha256','binding','state','members'} or type(p['version']) is not int or p['version']!=1:raise StorageFailure('operation receipt shape')
        try:operation_key.verify(bytes.fromhex(envelope['signature']),DOMAIN+canonical(p))
        except Exception as exc:raise StorageFailure('operation signature') from exc
        spec=specs.get(p['operation'])
        if not isinstance(spec,OperationSpec) or p['source_sha256']!=spec.source_sha256 or p['binding']!=binding(verified):raise StorageFailure('operation source/job/attempt binding')
        if p['state']!='SEALED_COMPLETE' or type(p['operation_id']) is not str or not p['operation_id']:raise StorageFailure('operation incomplete or unidentified')
        if type(p['members']) is not dict or set(p['members'])!=spec.labels:raise StorageFailure('operation missing or unexpected members')
        members={};references={}
        for label,expected in p['members'].items():
            original=reader.read_member(label);ref=reader.reference(label)
            if type(expected) is not dict or set(expected)!={'sha256','size_bytes'} or type(expected['size_bytes']) is not int or expected!={'sha256':sha(original),'size_bytes':len(original)}:raise StorageFailure('operation original member mismatch')
            members[label]=original;references[label]=ref
        self.reader=reader;self.payload=json.loads(canonical(p));self.members=MappingProxyType(members);self.references=MappingProxyType(references)
    def evaluate(self,evaluator):
        # The factory chooses a compiled evaluator; never an RPC function/module.
        return evaluator(self)
