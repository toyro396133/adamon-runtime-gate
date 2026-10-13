"""Concurrent credential requests cannot duplicate a guarded birth's issuer."""
from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace
from infrastructure.t3.runtime.deployment import BirthOrder
from infrastructure.t3.runtime.microvm import Blocked


def test_guarded_birth_has_one_atomic_credential_issuer():
    order=BirthOrder();record=SimpleNamespace(verify=lambda:None)
    order.born(record);order.guarded(lambda _:None)
    gate=threading.Event();entered=threading.Event();calls=[]
    def issue(_):
        calls.append(True);entered.set()
        assert gate.wait(2)
        return 'NONRESEARCH_TEST_CREDENTIAL'
    def request():
        try:return order.credential(issue)
        except Blocked:return 'REJECTED'
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(request);assert entered.wait(2)
        second=pool.submit(request);gate.set()
        results=[first.result(),second.result()]
    assert sorted(results)==['NONRESEARCH_TEST_CREDENTIAL','REJECTED']
    assert calls==[True]
