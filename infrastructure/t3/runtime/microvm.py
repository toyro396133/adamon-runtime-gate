"""Closed Firecracker configuration and bounded lifecycle, not a deployment.

Trusted resources are provided by the privileged supervisor after authenticated
assignment/atomic permit consumption. No caller-selected paths, shell or remote
compute URL is accepted. Public entry remains unconditionally blocked.
"""
from dataclasses import dataclass
import http.client
import json
import socket
import time
from typing import Protocol


class Blocked(RuntimeError):
    pass


def execute_research(*_args, **_kwargs):
    raise Blocked('NO_APPROVED_EXECUTION_FREEZE')


@dataclass(frozen=True)
class Subject:
    role: str
    subject: str
    source_sha256: str
    fixture_sha256: str


@dataclass(frozen=True)
class Resources:
    """Supervisor-selected jailed mount names; never received from workflow."""
    binary_sha256: str
    kernel_sha256: str
    root_sha256: str
    encrypted_evidence: bool
    immutable_mounts_verified: bool
    host_job_cgroup_verified: bool
    distinct_uids_verified: bool
    local_api_socket_verified: bool
    pidfd_verified: bool
    owner_runtime_preflight_verified: bool


class Authorization(Protocol):
    def check_live(self, role: str, subject: str) -> bool: ...


class Isolation(Protocol):
    """Native supervisor capability, not a path/PID supplied by requester."""
    def check_live(self) -> bool: ...
    def exited(self) -> bool: ...
    def exit_successful(self) -> bool: ...
    def kill_job_cgroup(self) -> None: ...
    def stop_subject_scope(self) -> None: ...
    def preserve_partial(self, reason: str) -> None: ...
    def revoke_credentials(self) -> None: ...
    def seal_complete(self) -> None: ...


class UnixHTTP:
    """Only a connected supervisor-provided AF_UNIX socket; no URLs/connect API."""
    def __init__(self, connected_socket):
        if connected_socket.family != socket.AF_UNIX:
            raise Blocked('REMOTE_COMPUTE_FORBIDDEN')
        self.sock = connected_socket
        self.sock.settimeout(10)

    def put(self, endpoint, value):
        if endpoint not in {'/machine-config', '/boot-source', '/drives/rootfs',
                            '/drives/evidence', '/vsock', '/actions'}:
            raise Blocked('UNREGISTERED_FIRECRACKER_OPERATION')
        body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        request = (f'PUT {endpoint} HTTP/1.1\r\nHost: localhost\r\n'
                   f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                   'Connection: keep-alive\r\n\r\n').encode() + body
        self.sock.sendall(request)
        response = http.client.HTTPResponse(self.sock)
        response.begin()
        # Firecracker success MUST be empty 204. Bound unexpected responses.
        length = response.getheader('Content-Length')
        if response.status != 204 or length not in (None, '0'):
            raise Blocked('FIRECRACKER_CONFIGURATION_FAILED')
        response.close()


class Lifecycle:
    """Serialized one-shot object used only behind supervisor lifecycle lock."""
    def __init__(self, registry, pins, authorization, isolation, api, resources,
                 clock=time.monotonic, guest=None, launch_attestation=None):
        self.registry = tuple(registry)
        self.pins = dict(pins)
        self.auth, self.isolation, self.api = authorization, isolation, api
        self.resources, self.clock = resources, clock
        self.state = 'NEW'
        self.guest, self.launch_attestation = guest, launch_attestation

    def _live(self, subject):
        if not self.auth.check_live(subject.role, subject.subject) or not self.isolation.check_live():
            raise Blocked('JOB_PERMIT_OR_PROCESS_NOT_LIVE')

    def _stop(self, reason):
        self.state = 'PARTIAL'
        # Kill must occur even when revocation/sealing fails. Never erase bytes.
        try:
            self.isolation.revoke_credentials()
        finally:
            try:
                self.isolation.kill_job_cgroup()
            finally:
                self.isolation.preserve_partial(reason)

    def run_trusted(self, subject, deadline, cancelled=lambda: False):
        """Not a public RPC. No installed production backend/permit can call this.

        Caller is privileged supervisor holding its serialized lifecycle lock;
        injected native backend must attest reviewed deployment prerequisites.
        Tests inject fake backend explicitly, never claim runtime isolation.
        """
        if self.state != 'NEW':
            raise Blocked('ONE_SHOT_RUNTIME')
        self.state = 'PREPARING'
        try:
            if subject not in self.registry or subject.role not in {'LIFE', 'MICRO', 'AUDIT', 'AGGREGATION'}:
                raise Blocked('UNREGISTERED_SUBJECT')
            if self.guest is None:
                raise Blocked('AUTHENTICATED_GUEST_TRANSPORT_MISSING')
            binding = self.guest.binding
            if (binding['role'], binding['subject'], binding['source_sha256'], binding['fixture_sha256']) != (subject.role, subject.subject, subject.source_sha256, subject.fixture_sha256):
                raise Blocked('GUEST_SUBJECT_BINDING_MISMATCH')
            if type(deadline) not in (int, float) or not self.clock() < deadline <= self.clock() + 72*3600:
                raise Blocked('JOB_DEADLINE')
            r = self.resources
            if not all((r.encrypted_evidence, r.immutable_mounts_verified,
                        r.host_job_cgroup_verified, r.distinct_uids_verified,
                        r.local_api_socket_verified, r.pidfd_verified,
                        r.owner_runtime_preflight_verified)):
                raise Blocked('NATIVE_PREFLIGHT_MISSING')
            for name in ('binary', 'kernel', 'root'):
                if getattr(r, name + '_sha256') != self.pins.get(name):
                    raise Blocked('IMMUTABLE_IMAGE_PIN')
            self._live(subject)
            # Fixed paths exist only INSIDE supervisor-created immutable jail.
            # AUDIT evidence originals are readonly; derived scratch lives in RAM.
            operations = (
                ('/machine-config', {'vcpu_count': 8, 'mem_size_mib': 24576, 'smt': False}),
                ('/boot-source', {'kernel_image_path': '/kernel',
                                 'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off ro'}),
                ('/drives/rootfs', {'drive_id': 'rootfs', 'path_on_host': '/rootfs',
                                    'is_root_device': True, 'is_read_only': True}),
                ('/drives/evidence', {'drive_id': 'evidence', 'path_on_host': '/evidence',
                                      'is_root_device': False, 'is_read_only': subject.role == 'AUDIT'}),
                ('/vsock', {'guest_cid': 3, 'uds_path': '/private-control.vsock'}),
            )
            for endpoint, value in operations:
                self._live(subject)
                if cancelled() or self.clock() >= deadline:
                    raise Blocked('JOB_CANCELLED_OR_DEADLINE')
                self.api.put(endpoint, value)
            self._live(subject)
            if cancelled() or self.clock() >= deadline:
                raise Blocked('JOB_CANCELLED_OR_DEADLINE')
            self.api.put('/actions', {'action_type': 'InstanceStart'})
            self.state = 'RUNNING'
            self.guest.execute(self.launch_attestation, timeout=min(30, deadline-self.clock()))
            completion = None
            while not self.isolation.exited():
                self._live(subject)
                if cancelled() or self.clock() >= deadline:
                    raise Blocked('JOB_CANCELLED_OR_DEADLINE')
                if completion is None:
                    completion = self.guest.poll_completion(.1)
                else:
                    time.sleep(.1)
            self._live(subject)  # authority must survive completion/sealing
            if completion is None:
                completion = self.guest.poll_completion(.1)
            if completion is None:
                raise Blocked('SIGNED_GUEST_COMPLETION_MISSING')
            if not self.isolation.exit_successful():
                raise Blocked('VMM_OR_GUEST_FAILED')
            self.isolation.seal_complete()
            self.state = 'COMPLETE'
            self.isolation.revoke_credentials()
            self.isolation.stop_subject_scope()
            return 'COMPLETE'
        except BaseException:
            self._stop('RUNTIME_FAILURE_OR_CANCEL')
            raise
