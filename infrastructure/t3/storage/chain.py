"""Concrete signed inventory -> exact-version reader; no research or path API."""
from dataclasses import asdict
from .evidence import StorageFailure, HEX, canonical, sha
from .inventory import create_inventory, verify_inventory


def scope_digest(authority_sha256, attempt_id):
    if type(authority_sha256) is not str or not HEX.fullmatch(authority_sha256):
        raise StorageFailure('exact authority required')
    if type(attempt_id) is not str or not attempt_id.isalnum() or len(attempt_id)>64:
        raise StorageFailure('exact attempt required')
    return sha(canonical({'authority':authority_sha256,'attempt':attempt_id}))


class InventoryProducer:
    """Only producer artifact labels registered at construction may be sealed."""
    def __init__(self, store, *, required_labels, scope_sha256, signer, key_id, member_key, member_key_id):
        self.store=store; self.labels=frozenset(required_labels); self.scope=scope_sha256
        self.signer=signer; self.key_id=key_id; self.member_key=member_key; self.member_key_id=member_key_id
        if not self.labels or not HEX.fullmatch(scope_sha256):raise StorageFailure('closed artifact registry required')
    def seal(self, artifacts, *, state='SEALED_COMPLETE'):
        if type(artifacts) is not dict or not set(artifacts)<=self.labels or (state=='SEALED_COMPLETE' and set(artifacts)!=self.labels):
            raise StorageFailure('missing or unregistered producer artifact')
        if not artifacts:raise StorageFailure('empty artifacts')
        members={}
        for label,data in artifacts.items():
            # Explicit local recovery primitive; production stores retain their
            # existing versioned create-only implementation.
            put=getattr(self.store,'put_exact',self.store.put)
            member=put(data,state=state)
            member.verify(self.member_key,self.member_key_id)
            if member.storage_scope_sha256!=self.scope:raise StorageFailure('storage attempt mismatch; preserve sealed source')
            members[label]=member
        return create_inventory(members,state=state,signer=self.signer,key_id=self.key_id,
            trusted_member_key=self.member_key,trusted_member_key_id=self.member_key_id)


class SignedInventoryReader:
    """Read-only capability. No write/delete/latest/path or evaluator truth API.

    Caller pins inventory SHA from the authenticated producer receipt. Every
    returned byte is verified against the member signature, scope and version.
    This class works with both the local cryptographic store and S3 reviewer.
    """
    def __init__(self, store, inventory, *, inventory_sha256, required_labels,
                 scope_sha256, inventory_key, inventory_key_id, member_key, member_key_id):
        if sha(canonical(inventory))!=inventory_sha256:raise StorageFailure('inventory receipt digest mismatch')
        self.inventory_sha256=inventory_sha256
        members=verify_inventory(inventory,public_key=inventory_key,key_id=inventory_key_id,
            required_labels=required_labels,trusted_member_key=member_key,trusted_member_key_id=member_key_id)
        if any(m.storage_scope_sha256!=scope_sha256 for m in members.values()):raise StorageFailure('cross-attempt inventory')
        self._store=store; self._members=members
        self._references={}
        for member in members.values():
            identity=(member.reference.object_id,member.reference.version_id)
            old=self._references.get(identity)
            # Before/after an idempotent operation legitimately have identical
            # bytes. Reuse only the exact signed envelope; contradictory alias
            # metadata must never replace the first authenticated capability.
            if old is not None and old!=member:raise StorageFailure('contradictory artifact byte reference')
            self._references.setdefault(identity,member)
    def read_member(self,label):
        if label not in self._members:raise StorageFailure('unregistered member')
        member=self._members[label]
        return self.read_version(member.reference.object_id,member.reference.version_id)
    def reference(self,label):
        if label not in self._members:raise StorageFailure('unregistered member')
        return asdict(self._members[label].reference)
    def read_version(self,object_id,version_id):
        member=self._references.get((object_id,version_id))
        if member is None:raise StorageFailure('unsigned or foreign version')
        data=self._store.read(member)
        if type(data) is not bytes or len(data)!=member.reference.size_bytes or sha(data)!=member.reference.sha256:
            raise StorageFailure('reader exact bytes failed')
        return data
