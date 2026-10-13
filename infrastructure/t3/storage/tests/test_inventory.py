from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infrastructure.t3.storage.evidence import LocalEncryptedStore,StorageFailure
from infrastructure.t3.storage.inventory import create_inventory,verify_inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.key=Ed25519PrivateKey.generate()
        self.store=LocalEncryptedStore(Path(self.tmp.name)/'db',b'x'*32,self.key,'broker')
        self.envelope=self.store.put(b'synthetic-only')
    def tearDown(self):self.tmp.cleanup()
    def create(self,members,state='SEALED_COMPLETE'):
        return create_inventory(members,state=state,signer=self.key,key_id='inventory',trusted_member_key=self.key.public_key(),trusted_member_key_id='broker')
    def verify(self,inventory,labels=('database',)):
        return verify_inventory(inventory,public_key=self.key.public_key(),key_id='inventory',required_labels=labels,trusted_member_key=self.key.public_key(),trusted_member_key_id='broker')
    def test_exact_inventory_roundtrip(self):
        self.assertEqual(self.verify(self.create({'database':self.envelope}))['database'],self.envelope)
    def test_missing_wal_rejected(self):
        with self.assertRaises(StorageFailure):self.verify(self.create({'database':self.envelope}),('database','wal'))
    def test_extra_member_rejected(self):
        with self.assertRaises(StorageFailure):self.verify(self.create({'database':self.envelope,'unapproved':self.envelope}))
    def test_caller_path_rejected(self):
        for label in ('../db','/db','db.sqlite'):
            with self.assertRaises(StorageFailure):self.create({label:self.envelope})
    def test_tampered_inventory_rejected(self):
        inventory=self.create({'database':self.envelope});inventory['members'][0]['label']='other'
        with self.assertRaises(StorageFailure):self.verify(inventory)
    def test_partial_cannot_become_complete(self):
        partial=self.store.put(b'partial','SEALED_PARTIAL')
        with self.assertRaises(StorageFailure):self.create({'database':partial})
    def test_partial_inventory_preserved_not_complete(self):
        partial=self.store.put(b'partial','CRASH_INCOMPLETE')
        inventory=self.create({'database':partial},'CRASH_INCOMPLETE')
        with self.assertRaises(StorageFailure):self.verify(inventory)

if __name__=='__main__':unittest.main()
