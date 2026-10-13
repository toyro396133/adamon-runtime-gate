"""Concrete descriptor-bound owner service entry, with closed lifecycle.

No Workflow command line/configuration/path is interpreted. The owner supplies
already provisioned descriptors and pinned images. This service starts the
native Listener only after signed deployment validation; Worker enrollment is
then performed by the production private bridge and REST identity binder.

Privileged namespace/network/cgroup provisioning and KVM live attestation are
explicit external prerequisites. Construction never manufactures those proofs.
Research fixed-step execution remains blocked inside Supervisor.
"""
import os
import select
import socket
import threading
import time
from ..security.native import NativeProcessFactory
from ..security.protocol import Denied
from ..security.supervisor import (DeploymentBoundWorkerSpawner,
                                  connect_deployed_supervisor)
from ..runtime.deployment import Deployment


class OwnerDeploymentService:
    def __init__(self, *, native_factory, deployment_envelope, owner_public_key,
                 image_descriptors, repository, token_provider, approved_identity,
                 credential_scope, evidence_scope, clock=time.time, network_scope=None):
        if not isinstance(native_factory, NativeProcessFactory):
            raise Denied('owner native factory required')
        if os.geteuid()!=0:raise Denied('privileged owner supervisor UID required')
        self.deployment=Deployment.verify(deployment_envelope,owner_public_key,clock)
        self.spawner=DeploymentBoundWorkerSpawner(native_factory,self.deployment,
                                                 image_descriptors,clock)
        # These private broker capabilities are never serialized into a request.
        if not callable(getattr(credential_scope,'revoke_all',None)) or not callable(getattr(evidence_scope,'preserve_partial',None)):
            raise Denied('owner credential/evidence capabilities required')
        self.factory=native_factory
        self.network_scope=network_scope;self.network_bridge=None
        if network_scope is not None:
            from .network import OwnerNetworkScope
            if not isinstance(network_scope,OwnerNetworkScope):raise Denied('owner network scope required')
            self.factory.listener_network=network_scope.listener(self.deployment)
        self.credentials,self.evidence=credential_scope,evidence_scope
        self._configuration=dict(repository=repository,owner_token_provider=token_provider,
                                 approved_identity=approved_identity,
                                 deployment_envelope=deployment_envelope,
                                 deployment_owner_public_key=owner_public_key,
                                 image_descriptors=image_descriptors,clock=clock)
        self._lock=threading.RLock();self.state='NEW'
        self.supervisor=None;self.channel=None

    def start(self):
        with self._lock:
            if self.state!='NEW':raise Denied('owner deployment one shot')
            self.state='STARTING'
            parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                self.spawner.verify_configuration()
                if self.network_scope is not None:
                    from .network_proxy import NamespaceConnectBridge,GitHubConnectBroker,OwnerGitHubConnector
                    self.network_bridge=NamespaceConnectBridge(self.network_scope.control_channel(),
                        GitHubConnectBroker(OwnerGitHubConnector())).start()
                record=self.factory.spawn('LISTENER',child.fileno())
                self.supervisor=connect_deployed_supervisor(listener=record,
                    native_factory=self.factory,cleanup=self._cleanup,
                    **self._configuration)
                self.channel=parent;self.state='RUNNING'
                return record
            except BaseException:
                parent.close()
                self._cleanup('OWNER_STARTUP_FAILURE',None)
                raise
            finally:child.close()

    def _cleanup(self,reason,_worker):
        with self._lock:
            if self.state=='STOPPED':return
            self.state='STOPPED'
            errors=[]
            try:self.credentials.revoke_all()
            except BaseException as exc:errors.append(exc)
            try:self.factory.revoke_owned(self.evidence.preserve_partial,reason)
            except BaseException as exc:errors.append(exc)
            if getattr(self,'network_bridge',None) is not None:
                try:self.network_bridge.close()
                except BaseException as exc:errors.append(exc)
                self.network_bridge=None
            if getattr(self,'network_scope',None) is not None:
                try:self.network_scope.close()
                except BaseException as exc:errors.append(exc)
            if self.channel is not None:
                try:self.channel.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.channel.close();self.channel=None
            if errors:raise ExceptionGroup('owner cleanup incomplete',errors)

    def cancel(self):
        # Supervisor.revoke is not enough before dispatch exists; owner factory
        # closes Listener and all enrolled births in either state.
        if self.supervisor is not None:self.supervisor.revoke('OWNER_CANCELLED')
        self._cleanup('OWNER_CANCELLED',None)

    def serve(self, *, deadline, cancel_fd, monotonic=time.monotonic):
        """Fixed retained channel; EOF/cancel/deadline all preserve PARTIAL.

        Cancellation byte is R; arbitrary commands, renewal and paths are not
        supported. The independent watchdog is mandatory outside this service.
        Listener bridge work runs separately so cancellation is not blocked by
        WorkerCompletion.wait(). Native births remain bounded to <=30 seconds.
        """
        if self.state!='RUNNING':raise Denied('owner service not running')
        if type(deadline) not in (int,float) or not monotonic()<deadline<=monotonic()+72*3600:
            raise Denied('owner service deadline')
        if type(cancel_fd) is not int or cancel_fd<0:raise Denied('owner cancel capability')
        os.fstat(cancel_fd);os.set_inheritable(cancel_fd,False)
        finished=threading.Event();failure=[]
        def bridge():
            try:
                while self.state=='RUNNING':
                    self.supervisor.serve_private(self.channel,'LISTENER')
            except BaseException as exc:failure.append(exc)
            finally:finished.set()
        worker=threading.Thread(target=bridge,name='owner-listener-bridge',daemon=True)
        worker.start()
        poll=select.poll();poll.register(cancel_fd,select.POLLIN|select.POLLHUP|select.POLLERR)
        poll.register(self.supervisor.listener.pidfd,select.POLLIN)
        reason='OWNER_LISTENER_EXIT'
        try:
            while not finished.is_set():
                left=deadline-monotonic()
                if left<=0:reason='OWNER_DEADLINE';break
                events=poll.poll(min(100,int(left*1000)+1))
                if events:
                    reason='OWNER_CANCELLED_OR_CHANNEL_LOST';break
            self._cleanup(reason,None)
            worker.join(timeout=35)
            if worker.is_alive():raise Denied('owner bridge cleanup deadline')
            if failure:raise ExceptionGroup('owner bridge failed closed',failure)
            return 'STOPPED_PARTIAL'
        finally:
            if self.state!='STOPPED':self._cleanup('OWNER_SERVICE_FAILURE',None)
