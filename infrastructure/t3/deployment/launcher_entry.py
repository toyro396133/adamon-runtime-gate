"""Joined owner-created nonresearch Launcher -> local VMM -> authenticated Guest.

This fixed API is called *inside* the Launcher spawned by native supervisor,
never by Workflow/RPC. Inputs are retained owner capabilities; no command/path
or public research permit may select a subject. Only the compiled canary runs.
Privileged/KVM execution has not been performed in the managed workspace.
"""
import fcntl
import os
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..runtime.launcher import LocalLauncher
from ..runtime.microvm import Lifecycle,Resources,Subject,Blocked
from ..runtime.native_control import NativeJobControl
from .nonresearch_images import NonresearchBootGuest,closed_binding,SUBJECT


class _EvidenceBoundary:
    def __init__(self,guest,evidence):self.guest,self.evidence=guest,evidence
    def guest_completion_authenticated(self):return self.guest.artifact is not None
    def preserve_partial(self,reason):return self.evidence.preserve_partial(reason)
    def seal_complete(self):
        if self.guest.artifact is None:raise Blocked('SIGNED_ORIGINAL_CANARY_ARTIFACT_MISSING')
        # Only original guest-produced bytes, never an evaluator reconstruction.
        self.evidence.preserve_authenticated_original(self.guest.artifact,self.guest.completion)
        return self.evidence.seal_complete()


def run_owner_nonresearch_launcher(*,deployment,worker_pidfd,native,
        signer_fd,delegation,owner_public_key,job_kill_fd,subject_kill_fd,credential_scope,evidence_scope,
        authorization,binding,resources,deadline,cancelled=lambda:False,
        monotonic=time.monotonic):
    closed_binding(binding)
    if not isinstance(resources,Resources):raise Blocked('OWNER_MEASURED_RESOURCES_REQUIRED')
    deployment.require_subject('CANARY',SUBJECT)
    for method in ('preserve_authenticated_original','preserve_partial','seal_complete'):
        if not callable(getattr(evidence_scope,method,None)):raise Blocked('OWNER_EVIDENCE_BROKER_REQUIRED')
    launcher=LocalLauncher.from_owner_assets(deployment,worker_pidfd)
    guest=None;control=None;lifecycle_started=False
    try:
        # Birth before irreversible guard, credentials read only after guard.
        pidfd=launcher.start()
        native.install_launcher_guard()
        if os.fstat(signer_fd).st_size!=32 or fcntl.fcntl(signer_fd,1034)&15!=15:
            raise Blocked('OWNER_SIGNER_NOT_SEALED')
        signer=Ed25519PrivateKey.from_private_bytes(os.pread(signer_fd,32,0))
        guest=NonresearchBootGuest(launcher,binding,signer,delegation,owner_public_key)
        control=NativeJobControl(worker_pidfd,pidfd,job_kill_fd,subject_kill_fd,
                                  credential_scope,_EvidenceBoundary(guest,evidence_scope))
        subject=Subject('LIFE',SUBJECT,binding['source_sha256'],binding['fixture_sha256'])
        pins=deployment.payload()['images']
        lifecycle=Lifecycle([subject],{'binary':pins['firecracker'],
                            'kernel':pins['kernel'],'root':pins['rootfs']},
                            authorization,control,launcher.await_api(),resources,
                            clock=monotonic,guest=guest)
        lifecycle_started=True
        status=lifecycle.run_trusted(subject,deadline,cancelled)
        return {'status':status,'scope':'NONRESEARCH_LOCAL_KVM_CANARY',
                'artifact_bytes':guest.artifact,'completion':guest.completion,
                'research_authorized':False}
    except BaseException:
        try:credential_scope.revoke()
        finally:
            if control is None:
                launcher.stop();evidence_scope.preserve_partial('NONRESEARCH_LAUNCHER_STARTUP_FAILURE')
            elif not lifecycle_started:
                try:control.kill_job_cgroup()
                finally:control.preserve_partial('NONRESEARCH_LAUNCHER_STARTUP_FAILURE')
        raise
    finally:
        if guest is not None:guest.close()
        launcher.stop();launcher.close_owner_assets()
