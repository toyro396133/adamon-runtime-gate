"""Audit artifact handling joins immutable bytes to signed producer receipts.

Semantic evaluators remain private and must execute inside the approved Job.
This adapter does not invent semantic PASS or enable terminal signing.
"""
import hashlib
from .receipts import ReceiptError, canonical
from ..storage.chain import SignedInventoryReader
from ..storage.evidence import canonical as storage_canonical


class EvidenceAudit:
    def __init__(self, verifier, *, reader_factory, evaluator, registered_subjects, micro_authorities=None):
        self.verifier=verifier; self.reader_factory=reader_factory
        self.evaluator=evaluator; self.subjects=dict(registered_subjects)
        self.micro_authorities=dict(micro_authorities or {})
    def inspect(self, producer_receipt, inventory):
        payload=producer_receipt.get('payload',{})
        subject=payload.get('case',payload.get('control_id'))
        role=self.subjects.get(subject)
        if role not in ('LIFE','MICRO'):raise ReceiptError('unregistered producer subject')
        verified=self.verifier.verify(producer_receipt,role,subject)
        # Factory is privileged construction, not caller-supplied RPC input.
        # It must return the concrete signed inventory reader, never a truth cache.
        reader=self.reader_factory(verified,inventory)
        if not isinstance(reader,SignedInventoryReader):raise ReceiptError('signed immutable reader required')
        metadata=None
        if role=='MICRO':
            pins=self.micro_authorities.get(subject)
            from .micro_authority import MicroAuthorityPins
            if not isinstance(pins,MicroAuthorityPins):raise ReceiptError('active privileged MICRO authority missing')
            pins.verify_receipt(verified)
            metadata=pins.inspect_reader(reader)
        result=self.evaluator(subject,reader)
        if type(result) is not dict or set(result)!={'gates','controls','failures','errors','skips'}:
            raise ReceiptError('closed evaluator output required')
        if any(type(result[k]) is not int or result[k]!=0 for k in ('failures','errors','skips')):
            raise ReceiptError('audit not complete')
        for group in ('gates','controls'):
            if type(result[group]) is not dict:raise ReceiptError('closed assertion map required')
        manifest={'producer_receipt_sha256':hashlib.sha256(canonical(verified)).hexdigest(),**result}
        if metadata is not None:manifest['micro_authority']=metadata
        return manifest
    @staticmethod
    def seal_manifest(manifest, *, store):
        # Aggregator consumes this exact content-addressed immutable version.
        sealed=store.put(storage_canonical(manifest),state='SEALED_COMPLETE')
        return sealed
