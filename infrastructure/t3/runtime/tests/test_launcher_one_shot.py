"""Launcher birth reservation tests; no VMM/KVM or scientific execution."""
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from infrastructure.t3.runtime.launcher import LocalLauncher
from infrastructure.t3.runtime.microvm import Blocked


class FailingImage:
    def __init__(self):self.calls=0;self.entered=threading.Event();self.release=threading.Event()
    def verify(self):
        self.calls+=1;self.entered.set();self.release.wait(2)
        raise Blocked('NONRESEARCH_IMAGE_REJECTED')


def test_failed_validation_consumes_birth_reservation():
    image=FailingImage();image.release.set();launcher=LocalLauncher(image,None,None,None)
    with pytest.raises(Blocked,match='NONRESEARCH_IMAGE_REJECTED'):launcher.start()
    launcher.stop()
    with pytest.raises(Blocked,match='^VMM_ONE_SHOT$'):launcher.start()
    assert image.calls==1 and launcher.process is None


def test_concurrent_start_cannot_enter_second_birth_validation():
    image=FailingImage();launcher=LocalLauncher(image,None,None,None)
    def start():
        try:launcher.start()
        except Blocked as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first=executor.submit(start);assert image.entered.wait(1)
        second=executor.submit(start);image.release.set()
        errors={first.result(timeout=3),second.result(timeout=3)}
    assert errors=={'NONRESEARCH_IMAGE_REJECTED','VMM_ONE_SHOT'}
    assert image.calls==1 and launcher.process is None


def test_concurrent_stop_reaps_one_actual_owned_child():
    import os
    import subprocess
    import sys
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    launcher=LocalLauncher(None,None,None,None)
    launcher.process=child;launcher.pidfd=os.pidfd_open(child.pid)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures=[executor.submit(launcher.stop) for _ in range(2)]
            for future in futures:future.result(timeout=3)
        assert child.poll() is not None and launcher.process is None
    finally:
        if child.poll() is None:child.kill();child.wait()
