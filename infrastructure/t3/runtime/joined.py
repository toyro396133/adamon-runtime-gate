"""Deferred authenticated guest connection for the concrete Launcher/VMM pair.

A Firecracker guest UDS cannot exist before InstanceStart. This adapter supplies
immutable expected binding to Lifecycle and connects only when execute() runs,
after machine configuration and boot. No caller-selected socket or remote host.
"""
import json
from .guest import GuestClient, canonical, validate_binding
from .launcher import LocalLauncher
from .microvm import Blocked


class DeferredLocalGuest:
    def __init__(self,launcher,binding,completion_public_key):
        if not isinstance(launcher,LocalLauncher):raise Blocked('LOCAL_OWNER_LAUNCHER_REQUIRED')
        validate_binding(binding)
        if type(completion_public_key) is not bytes or len(completion_public_key)!=32:
            raise Blocked('GUEST_COMPLETION_KEY')
        self.launcher=launcher;self._binding=canonical(binding)
        self.public_key=completion_public_key;self.client=None;self.used=False

    @property
    def binding(self):return json.loads(self._binding)

    def execute(self,launch_attestation,timeout=30):
        if self.used:raise Blocked('GUEST_ONE_SHOT_OR_TIMEOUT')
        self.used=True
        stream=self.launcher.guest()
        try:
            self.client=GuestClient(stream,self.binding,self.public_key)
            self.client.execute(launch_attestation,timeout)
        except BaseException:
            stream.close();self.client=None
            raise

    def poll_completion(self,timeout=.1):
        if self.client is None:raise Blocked('GUEST_NOT_BOOTED')
        return self.client.poll_completion(timeout)

    def close(self):
        if self.client is not None:
            self.client.stream.close();self.client=None
