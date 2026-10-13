"""Signed exact-member inventories: byte references only, no paths or research."""
import base64
from dataclasses import asdict
import re
from .evidence import DOMAIN, SealedEvidence, StorageFailure, canonical

INVENTORY_DOMAIN = b'ADAMON-T3-EVIDENCE-INVENTORY-V1\x00'
LABEL = re.compile(r'^[A-Za-z0-9_-]{1,80}$')


def create_inventory(members: dict[str, SealedEvidence], *, state, signer, key_id, trusted_member_key, trusted_member_key_id):
    if not members or len(members) > 10000 or state not in ('SEALED_COMPLETE','SEALED_PARTIAL','CRASH_INCOMPLETE'):
        raise StorageFailure('invalid sealed inventory')
    entries = []
    for label, envelope in sorted(members.items()):
        if not LABEL.fullmatch(label):
            raise StorageFailure('opaque registered member label required; no paths')
        envelope.verify(trusted_member_key, trusted_member_key_id)
        if state == 'SEALED_COMPLETE' and envelope.state != 'SEALED_COMPLETE':
            raise StorageFailure('partial member cannot form complete inventory')
        entries.append({'label':label,'evidence':{**envelope.payload(),'signature':envelope.signature}})
    payload = {'version':1,'state':state,'members':entries,'signer_key_id':key_id}
    return {**payload,'signature':base64.b64encode(signer.sign(INVENTORY_DOMAIN+canonical(payload))).decode('ascii')}


def verify_inventory(inventory, *, public_key, key_id, required_labels, trusted_member_key, trusted_member_key_id, require_complete=True):
    if type(inventory) is not dict or set(inventory) != {'version','state','members','signer_key_id','signature'} or type(inventory['version']) is not int or inventory['version'] != 1 or inventory['signer_key_id'] != key_id:
        raise StorageFailure('unknown inventory schema or identity')
    payload = {key:value for key,value in inventory.items() if key!='signature'}
    try:
        public_key.verify(base64.b64decode(inventory['signature'],validate=True),INVENTORY_DOMAIN+canonical(payload))
    except Exception as exc:
        raise StorageFailure('invalid inventory signature') from exc
    if inventory['state'] not in ('SEALED_COMPLETE','SEALED_PARTIAL','CRASH_INCOMPLETE') or (require_complete and inventory['state'] != 'SEALED_COMPLETE'):
        raise StorageFailure('unqualified inventory state')
    from .evidence import EvidenceRef
    if type(inventory['members']) is not list or not inventory['members'] or len(inventory['members'])>10000:
        raise StorageFailure('invalid inventory member collection')
    found = {}
    for entry in inventory['members']:
        if type(entry) is not dict or set(entry) != {'label','evidence'} or not LABEL.fullmatch(entry['label']) or entry['label'] in found:
            raise StorageFailure('duplicate or invalid inventory member')
        data = entry['evidence']
        if type(data) is not dict or set(data) != {'version','reference','state','retention_until','signer_key_id','signature','storage_scope_sha256'} or type(data['version']) is not int or data['version'] != 1:
            raise StorageFailure('unknown evidence member schema')
        try:
            envelope = SealedEvidence(EvidenceRef(**data['reference']),data['state'],data['retention_until'],data['signer_key_id'],data['signature'],data['storage_scope_sha256'])
        except Exception as exc:
            raise StorageFailure('invalid member reference') from exc
        envelope.verify(trusted_member_key,trusted_member_key_id)
        if require_complete and envelope.state != 'SEALED_COMPLETE':
            raise StorageFailure('partial member')
        found[entry['label']] = envelope
    if set(found) != set(required_labels):
        raise StorageFailure('exact approved artifact inventory mismatch')
    return found
