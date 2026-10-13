"""Immutable control inventory byte verification, never semantic completion.

Private subject IDs and approved registry authority are injected by the private
factory. This generic broker verifies signed/version-pinned bytes only; its
output is forbidden as an acceptance gate or a control completion receipt.
"""
import json
from collections.abc import Mapping
from types import MappingProxyType
from .evidence import HEX, StorageFailure, sha

COUNTS=MappingProxyType({'life':27,'micro':2,'offline':12,'corruption':8})
FIELDS=frozenset({'object_id','version_id','sha256','bytes','subject','kind'})


def verify_control_bytes(*, manifest_reference, registered_subjects, immutable_reader):
    """No caller manifest, arbitrary path, write capability, gate boolean or oracle."""
    if (not isinstance(registered_subjects,Mapping) or set(registered_subjects)!=set(COUNTS)
        or any(len(registered_subjects[group])!=count or len(set(registered_subjects[group]))!=count
               for group,count in COUNTS.items())):
        raise StorageFailure('closed private registered 27/2/12/8 authority required')
    subjects={group:frozenset(values) for group,values in registered_subjects.items()}
    def read(ref):
        if (type(ref) is not dict or set(ref)!=FIELDS or type(ref['sha256']) is not str
            or not HEX.fullmatch(ref['sha256']) or ref['object_id']!=ref['sha256']
            or type(ref['version_id']) is not str or not ref['version_id'] or ref['version_id'] in ('null','latest')
            or type(ref['bytes']) is not int or ref['bytes']<0):
            raise StorageFailure('closed exact immutable control reference required')
        data=immutable_reader.read_version(ref['object_id'],ref['version_id'])
        if type(data) is not bytes or len(data)!=ref['bytes'] or sha(data)!=ref['sha256']:
            raise StorageFailure('original control bytes missing/version/hash mismatch')
        return data
    raw=read(manifest_reference)
    if manifest_reference['kind']!='control_inventory' or manifest_reference['subject']!='CONTROL_INVENTORY':
        raise StorageFailure('closed control inventory subject')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise StorageFailure('duplicate inventory JSON key')
            result[key]=value
        return result
    try:inventory=json.loads(raw,object_pairs_hook=pairs)
    except (ValueError,TypeError,UnicodeError) as exc:raise StorageFailure('invalid original inventory bytes') from exc
    if type(inventory) is not dict or set(inventory)!=set(COUNTS):raise StorageFailure('closed control inventory groups')
    seen={(manifest_reference['object_id'],manifest_reference['version_id'])};verified=[]
    for group in COUNTS:
        entries=inventory[group]
        if type(entries) is not dict or set(entries)!=subjects[group]:raise StorageFailure('missing/foreign control subject')
        for subject,ref in entries.items():
            if type(ref) is not dict or ref.get('kind')!=group or ref.get('subject')!=subject:
                raise StorageFailure('control kind/subject mismatch')
            identity=(ref.get('object_id'),ref.get('version_id'))
            if identity in seen:raise StorageFailure('aliased control evidence; no fake completion')
            seen.add(identity);data=read(ref)
            verified.append(dict(kind=group,subject=subject,sha256=sha(data),bytes=len(data)))
    return dict(scope='BYTE_VERIFIED_NOT_SEMANTIC_CONTROL_COMPLETION',counts=dict(COUNTS),
                manifest_sha256=sha(raw),verified=verified,can_close_gate=False)
