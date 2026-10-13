"""Concrete owner-only cgroup-v2 scope provisioner; never invoked by Workflow.

The parent directory FD is a dedicated owner-approved delegated subtree. This
module cannot grant cgroup permissions or approve/provision a host. No operation
runs during import or tests; the live create() path requires UID0 and cgroup2fs.
"""
import ctypes
import os
import stat
from dataclasses import dataclass
from ..runtime.microvm import Blocked

CGROUP2_SUPER_MAGIC=0x63677270


def require_cgroup2(fd):
    if type(fd) is not int or fd<0 or not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise Blocked('OWNER_CGROUP_DIRECTORY_FD')
    # statfs ABI Linux x86_64: the leading native long is f_type. The backing
    # buffer exceeds both common statfs structs, avoiding speculative fields.
    buffer=ctypes.create_string_buffer(256)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.fstatfs(fd,buffer)<0:raise OSError(ctypes.get_errno(),'owner cgroup statfs')
    if ctypes.c_long.from_buffer(buffer).value!=CGROUP2_SUPER_MAGIC:
        raise Blocked('OWNER_CGROUP2_FILESYSTEM_REQUIRED')


def _write(directory,name,value):
    fd=os.open(name,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=directory)
    try:
        if os.write(fd,value)!=len(value):raise Blocked('OWNER_CGROUP_SHORT_WRITE')
    finally:os.close(fd)


def scope_names(job_id):
    if type(job_id) is not int or not 0<job_id<=2**53-1:
        raise Blocked('OWNER_AUTHENTICATED_JOB_ID')
    return ('adamon-job-'+str(job_id),'adamon-control-'+str(job_id))


@dataclass
class OwnerCgroupScope:
    parent_fd:int
    job_fd:int
    control_fd:int
    role_fds:dict
    names:tuple
    active:bool=True

    @classmethod
    def create(cls,parent_fd,authenticated_job_id):
        if os.geteuid()!=0:raise Blocked('OWNER_CGROUP_UID0_REQUIRED')
        require_cgroup2(parent_fd)
        names=scope_names(authenticated_job_id)
        controller=os.open('cgroup.controllers',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
        try:available=set(os.read(controller,4096).decode('ascii').split())
        finally:os.close(controller)
        if not {'cpu','memory','pids'}<=available:raise Blocked('OWNER_CGROUP_CONTROLLERS_MISSING')
        # Dedicated parent is owner-approved. This is never the global cgroup
        # root and may not contain any untrusted process. Kernel rejects EBUSY.
        parent=os.dup(parent_fd);opened=[];created=[];roles={}
        try:
            _write(parent,'cgroup.subtree_control',b'+cpu +memory +pids')
            for name in names:
                os.mkdir(name,0o700,dir_fd=parent);created.append((parent,name))
                fd=os.open(name,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                opened.append(fd)
            job,control=opened
            _write(job,'cpu.max',b'800000 100000')
            _write(job,'memory.max',str(32*1024**3).encode('ascii'))
            _write(job,'pids.max',b'256')
            _write(job,'cgroup.subtree_control',b'+cpu +memory +pids')
            _write(control,'cgroup.subtree_control',b'+cpu +memory +pids')
            for role,owner in (('LISTENER',control),('WORKER',job),('LAUNCHER',job),('WATCHDOG',control),('STORAGE',control)):
                name=role.lower();os.mkdir(name,0o700,dir_fd=owner);created.append((owner,name))
                roles[role]=os.open(name,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=owner)
                opened.append(roles[role])
            return cls(parent,job,control,roles,names)
        except BaseException:
            # No child has been born through this capability yet. Remove only
            # directories created by this invocation; never reuse/erase others.
            for owner,name in reversed(created):
                try:os.rmdir(name,dir_fd=owner)
                except OSError:pass
            for fd in opened:os.close(fd)
            os.close(parent);raise

    def cancel_job(self):
        if not self.active:raise Blocked('OWNER_CGROUP_SCOPE_CLOSED')
        # Watchdog/storage live in control scope to preserve PARTIAL after this.
        _write(self.job_fd,'cgroup.kill',b'1')

    def close(self):
        if not self.active:return
        # Do not destroy populated cgroups or erase original partial evidence.
        errors=[]
        for fd in (self.job_fd,self.control_fd):
            try:_write(fd,'cgroup.kill',b'1')
            except OSError as exc:errors.append(exc)
        for role,fd in reversed(tuple(self.role_fds.items())):
            try:os.rmdir(role.lower(),dir_fd=self.control_fd if role in {'LISTENER','WATCHDOG','STORAGE'} else self.job_fd)
            except OSError as exc:errors.append(exc)
        for name in self.names:
            try:os.rmdir(name,dir_fd=self.parent_fd)
            except OSError as exc:errors.append(exc)
        for fd in (*self.role_fds.values(),self.job_fd,self.control_fd,self.parent_fd):os.close(fd)
        self.active=False
        if errors:raise ExceptionGroup('owner cgroup cleanup incomplete; operator required',errors)
