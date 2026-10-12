"""Real role verifier/storage/Audit/AND; synthetic bytes, no research contracts."""
import copy
from dataclasses import asdict
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.roles.tests.test_micro_audit_aggregation_integration import SyntheticCampaign,digest
from infrastructure.t3.roles.receipts import ReceiptError
from infrastructure.t3.storage.chain import InventoryProducer
from infrastructure.t3.storage.operations import OperationProducer,OperationReader,OperationSpec
from infrastructure.t3.storage.evidence import StorageFailure


class Campaign(SyntheticCampaign):
    def __init__(self,path):
        self.operation_active=False;super().__init__(path)
        self.subject=self.life[0];self.specs={'capture':OperationSpec('7'*64,frozenset({'artifact'}))}
        self.producer=InventoryProducer(self.store,required_labels={'artifact','operation_receipt'},scope_sha256=self.scope,signer=self.inventory_key,key_id='inventory',member_key=self.storage_key.public_key(),member_key_id='storage')
        self.ops=OperationProducer(inventory_producer=self.producer,specs=self.specs,producer_identity=self.payloads[('LIFE',self.subject)],signer=self.keys['LIFE'],ledger=path/'operations.sqlite')
        self.inventory_new=self.ops.capture('op1','capture',{'artifact':('OPERATION:NONRESEARCH:'+self.subject).encode()})
        self.producer_new=self.sign(dict(self.payloads[('LIFE',self.subject)],inventory_sha256=digest(self.inventory_new)))
        self.operation_active=True
        manifest=self.audit.inspect(self.producer_new,self.inventory_new)
        sealed=self.audit.seal_manifest(manifest,store=self.store)
        self.sealed_manifests[self.subject]=sealed
        signed_audit=self.sign(dict(self.payloads[('AUDIT',self.subject)],audit_manifest=asdict(sealed.reference)))
        self.receipts[:2]=[self.producer_new,signed_audit]
    def reader_factory(self,payload,inventory):
        if self.operation_active and payload.get('case')==self.subject:
            return self.reader(inventory,{'artifact','operation_receipt'},payload['inventory_sha256'])
        return super().reader_factory(payload,inventory)
    def inspect_operation(self,envelope=None,inventory=None,specs=None,key=None):
        return OperationReader(producer_receipt=self.producer_new if envelope is None else envelope,inventory=self.inventory_new if inventory is None else inventory,receipt_verifier=self.verifier,reader_factory=self.reader_factory,specs=self.specs if specs is None else specs,operation_key=self.keys['LIFE'].public_key() if key is None else key)
    def evaluator(self,subject,reader):
        if not self.operation_active or subject!=self.subject:return super().evaluator(subject,reader)
        operation=self.inspect_operation()
        assert operation.members['artifact']==('OPERATION:NONRESEARCH:'+subject).encode()
        # Existing synthetic registry asserts only these synthetic original bytes.
        return dict(gates={g:dict(self.registry.gate_assertions[g]) for g in self.gates},controls={},failures=0,errors=0,skips=0)


def test_operation_originals_through_actual_signed_audit_and_aggregation(tmp_path):
    c=Campaign(tmp_path);assert c.aggregator().evaluate(c.receipts)=={'overall_pass':True}
    original=c.inspect_operation();assert original.payload['operation_id']=='op1'
    assert c.ops.capture('op1','capture',{'artifact':('OPERATION:NONRESEARCH:'+c.subject).encode()})==c.inventory_new
    with pytest.raises(ReceiptError,match='signing disabled'):c.aggregator().finalize(c.receipts,{},Ed25519PrivateKey.generate(),None)


@pytest.mark.parametrize('mutation',('source','key','receipt','version','members','partial_upgrade','retry','missing_audit','duplicate_audit','missing_manifest'))
def test_isolated_operation_pipeline_mutations(tmp_path,mutation):
    c=Campaign(tmp_path);assert c.aggregator().evaluate(c.receipts)=={'overall_pass':True};c.inspect_operation()
    with pytest.raises((StorageFailure,ReceiptError)):
        if mutation=='source':c.inspect_operation(specs={'capture':OperationSpec('8'*64,frozenset({'artifact'}))})
        elif mutation=='key':c.inspect_operation(key=Ed25519PrivateKey.generate().public_key())
        elif mutation=='receipt':
            bad=copy.deepcopy(c.producer_new);bad['signature']='0'*128;c.inspect_operation(envelope=bad)
        elif mutation=='version':
            bad=copy.deepcopy(c.inventory_new);bad['members'][0]['evidence']['reference']['version_id']='latest';c.inspect_operation(inventory=bad)
        elif mutation=='members':c.ops.capture('new','capture',{'wrong':b'original'})
        elif mutation=='partial_upgrade':
            c.ops.capture('partial','capture',{'artifact':b'partial'},state='SEALED_PARTIAL');c.ops.capture('partial','capture',{'artifact':b'partial'})
        elif mutation=='retry':c.ops.capture('op1','capture',{'artifact':b'replaced'})
        elif mutation=='missing_audit':c.aggregator().evaluate(c.receipts[:1]+c.receipts[2:])
        elif mutation=='duplicate_audit':c.aggregator().evaluate(c.receipts+[c.receipts[1]])
        else:
            bad=copy.deepcopy(c.receipts);bad[1]=c.sign({**bad[1]['payload'],'audit_manifest':{'object_id':'0'*64,'version_id':'missing','sha256':'0'*64,'size_bytes':1}});c.aggregator().evaluate(bad)
    c.inspect_operation();assert c.aggregator().evaluate(c.receipts)=={'overall_pass':True}
