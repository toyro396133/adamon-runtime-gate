/* Library only: NO CLI, socket enrollment, commands or research authority.
 * Caller is privileged pinned supervisor holding owner-verified immutable FDs.
 * Spawn returns a stopped child and a birth-created pidfd, never PID lookup.
 */
#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <grp.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
struct p4_child { pid_t pid; int pidfd; int resume_fd; int error_fd; };
static int immutable_fd(int fd) {
 /* Owner-pinned sealed memfds have no filesystem readonly flag. Require every
  * mutation seal; a merely O_RDONLY descriptor is not immutable. */
 int seals=fcntl(fd,F_GET_SEALS);
 int required=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
 if(seals>=0 && (seals & required)==required)return 0;
 struct statvfs v; unsigned int flags=0;
 if(fstatvfs(fd,&v)<0) return -1;
 if(v.f_flag & ST_RDONLY) return 0;
 if(ioctl(fd,FS_IOC_GETFLAGS,&flags)==0 && (flags & (FS_IMMUTABLE_FL|FS_VERITY_FL))) return 0;
 errno=EPERM;return -1;
}
int p4_provision_jail(int,int,int,int,unsigned long,unsigned long);
static int p4_provision_vm_assets(int,int,int,int);
static int p4_bind_evidence_volume(int,int);
static int spawn_internal(int exe_fd,int job_cgroup_fd,uid_t uid,gid_t gid,
                    int bootstrap_fd,int role,int channel_in,int channel_out,
                    int jail_fd,int source_fd,int fixture_fd,int evidence_fd,
                    unsigned long parent_mnt,unsigned long parent_net,
                    int firecracker_fd,int kernel_fd,int rootfs_fd,int kvm_fd,int listener_net_fd,int volume_fd,int volume_readonly,int worker_pidfd,struct p4_child *out) {
 int target_fd=role==1?198:role==2?199:200;
 if(role<1||role>3||(role==2&&(channel_in<0||channel_out<0))){errno=EINVAL;return -1;}
 int sync[2],err[2],pidfd=-1;
 if(!out||uid==0||gid==0||exe_fd==196||exe_fd==197||exe_fd==198||exe_fd==199||exe_fd==200||exe_fd==203||immutable_fd(exe_fd)<0){errno=EPERM;return -1;}
 if(pipe2(sync,O_CLOEXEC)<0)return -1;
 if(pipe2(err,O_CLOEXEC)<0){close(sync[0]);close(sync[1]);return -1;}
 struct clone_args args={0};args.flags=CLONE_PIDFD|CLONE_INTO_CGROUP|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS;
 if(jail_fd>=0)args.flags|=CLONE_NEWPID;
 args.pidfd=(uintptr_t)&pidfd;args.cgroup=job_cgroup_fd;args.exit_signal=SIGCHLD;
 pid_t pid=syscall(SYS_clone3,&args,sizeof(args));
 if(pid<0){close(sync[0]);close(sync[1]);close(err[0]);close(err[1]);return -1;}
 if(pid==0){
  close(sync[1]);close(err[0]);
  int saved_error=fcntl(err[1],F_DUPFD_CLOEXEC,256);
  if(saved_error<0){_exit(127);}
  close(err[1]);err[1]=saved_error;
  int saved_bootstrap=fcntl(bootstrap_fd,F_DUPFD_CLOEXEC,256);
  if(saved_bootstrap<0){_exit(127);}
  bootstrap_fd=saved_bootstrap;
  int saved_worker=-1;
  if(worker_pidfd>=0){saved_worker=fcntl(worker_pidfd,F_DUPFD_CLOEXEC,256);if(saved_worker<0)_exit(127);worker_pidfd=saved_worker;}
  int saved_in=-1,saved_out=-1;
  if(role==2){saved_in=fcntl(channel_in,F_DUPFD_CLOEXEC,256);saved_out=fcntl(channel_out,F_DUPFD_CLOEXEC,256);if(saved_in<0||saved_out<0)_exit(127);channel_in=saved_in;channel_out=saved_out;}
  char go;
  if(read(sync[0],&go,1)!=1||go!='R')_exit(126);
  close(sync[0]);
  if(role==1&&listener_net_fd>=0&&setns(listener_net_fd,CLONE_NEWNET)<0)goto fail;
  if(jail_fd>=0 && firecracker_fd>=0){
   struct stat mnt,net;
   if(stat("/proc/self/ns/mnt",&mnt)<0||stat("/proc/self/ns/net",&net)<0)goto fail;
   if((unsigned long)mnt.st_ino==parent_mnt||(unsigned long)net.st_ino==parent_net){errno=EPERM;goto fail;}
   if(fchdir(jail_fd)<0||p4_provision_vm_assets(firecracker_fd,kernel_fd,rootfs_fd,kvm_fd)<0)goto fail;
   if(volume_fd<0||p4_bind_evidence_volume(volume_fd,volume_readonly)<0)goto fail;
  }
  if(jail_fd>=0 && p4_provision_jail(jail_fd,source_fd,fixture_fd,evidence_fd,parent_mnt,parent_net)<0)goto fail;
  /* Bootstrap already parent-created; all other descriptors closed. */
  if(dup2(bootstrap_fd,target_fd)<0)goto fail;
  if(fcntl(target_fd,F_SETFD,0)<0)goto fail;
  if(role==2){
   if(dup2(channel_in,196)<0||dup2(channel_out,197)<0||fcntl(196,F_SETFD,0)<0||fcntl(197,F_SETFD,0)<0)goto fail;
  }
  int keep[6]={target_fd,exe_fd,err[1],0,0,0};int count=3;
  if(role==2){keep[count++]=196;keep[count++]=197;}
  if(worker_pidfd>=0){
   if(syscall(SYS_pidfd_send_signal,worker_pidfd,0,NULL,0)<0||dup2(worker_pidfd,203)<0||fcntl(203,F_SETFD,0)<0)goto fail;
   keep[count++]=203;
  }
  for(int a=0;a<count;a++)for(int b=a+1;b<count;b++)if(keep[a]>keep[b]){int t=keep[a];keep[a]=keep[b];keep[b]=t;}
  unsigned int lower=0;
  for(int a=0;a<count;a++){
   if((unsigned int)keep[a]>lower && syscall(SYS_close_range,lower,(unsigned int)keep[a]-1,0)<0)goto fail;
   lower=(unsigned int)keep[a]+1;
  }
  if(syscall(SYS_close_range,lower,UINT_MAX,0)<0)goto fail;
  if(setgroups(0,NULL)<0||setresgid(gid,gid,gid)<0||setresuid(uid,uid,uid)<0)goto fail;
  if(prctl(PR_SET_DUMPABLE,0)<0||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0)goto fail;
  char *listener_argv[]={"Runner.Listener","run","--ephemeral",NULL};
  char *worker_argv[]={"Runner.Worker","spawnclient", "196", "197", NULL};
  char *launcher_argv[]={"p4-pinned-launcher",NULL};
  char **argv=role==1?listener_argv:role==2?worker_argv:launcher_argv;char *env[]={NULL};
  syscall(SYS_execveat,exe_fd,"",argv,env,AT_EMPTY_PATH);
 fail: {int e=errno;write(err[1],&e,sizeof(e));_exit(127);}
 }
 close(sync[0]);close(err[1]);*out=(struct p4_child){pid,pidfd,sync[1],err[0]};return 0;
}
int p4_check_immutable_fd(int fd){return immutable_fd(fd);}
int p4_spawn_role_paused(int e,int c,uid_t u,gid_t g,int b,int r,int i,int o,struct p4_child *child){
 return spawn_internal(e,c,u,g,b,r,i,o,-1,-1,-1,-1,0,0,-1,-1,-1,-1,-1,-1,0,-1,child);
}
int p4_spawn_launcher_jail_paused(int e,int c,uid_t u,gid_t g,int b,
 int j,int s,int f,int v,unsigned long m,unsigned long n,struct p4_child *child){
 if(j<0||s<0||f<0||v<0||m==0||n==0){errno=EINVAL;return -1;}
 return spawn_internal(e,c,u,g,b,3,-1,-1,j,s,f,v,m,n,-1,-1,-1,-1,-1,-1,0,-1,child);
}
int p4_spawn_launcher_vm_paused(int e,int c,uid_t u,gid_t g,int b,
 int j,int s,int f,int v,unsigned long m,unsigned long n,int fc,int k,int r,int kv,int volume,int readonly,int worker_pidfd,struct p4_child *child){
 if(j<0||s<0||f<0||v<0||m==0||n==0||fc<0||k<0||r<0||kv<0||volume<0||worker_pidfd<0||(readonly!=0&&readonly!=1)){errno=EINVAL;return -1;}
 return spawn_internal(e,c,u,g,b,3,-1,-1,j,s,f,v,m,n,fc,k,r,kv,-1,volume,readonly,worker_pidfd,child);
}
int p4_spawn_listener_network_paused(int e,int c,uid_t u,gid_t g,int b,int network_fd,struct p4_child *child){
 if(network_fd<0){errno=EINVAL;return -1;}
 return spawn_internal(e,c,u,g,b,1,-1,-1,-1,-1,-1,-1,0,0,-1,-1,-1,-1,network_fd,-1,0,-1,child);
}
int p4_spawn_paused(int e,int c,uid_t u,gid_t g,int b,struct p4_child *o){return p4_spawn_role_paused(e,c,u,g,b,3,-1,-1,o);}
int p4_resume(struct p4_child *child){char go='R';if(write(child->resume_fd,&go,1)!=1)return -1;close(child->resume_fd);child->resume_fd=-1;return 0;}
int p4_kill(struct p4_child *child){return syscall(SYS_pidfd_send_signal,child->pidfd,SIGKILL,NULL,0);}
int p4_exec_ack(struct p4_child *child){int e=0;ssize_t n=read(child->error_fd,&e,sizeof(e));close(child->error_fd);child->error_fd=-1;if(n==0){struct pollfd p={child->pidfd,POLLIN,0};if(poll(&p,1,0)!=0){errno=ESRCH;return -1;}return 0;}errno=n==sizeof(e)?e:EIO;return -1;}
int p4_sealed_key_memfd(const unsigned char *bytes,size_t n){
 if(!bytes||n!=32){errno=EINVAL;return -1;}
 int fd=syscall(SYS_memfd_create,"p4-bootstrap-key",MFD_CLOEXEC|MFD_ALLOW_SEALING);
 if(fd<0)return -1;
 if(write(fd,bytes,n)!=(ssize_t)n||fcntl(fd,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)<0){close(fd);return -1;}
 lseek(fd,0,SEEK_SET);return fd;
}
/* Call in pinned launcher immediately after initial exec. Forbidden mutation
 * syscalls have no fallback. This deny-list is NOT the complete reviewed LSM
 * allow-list and therefore cannot authorize production by itself. */
int p4_launcher_mutation_guard(void){
 #define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
 struct sock_filter filter[]={
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 DENY(__NR_execve),DENY(__NR_execveat),DENY(__NR_ptrace),DENY(__NR_setuid),DENY(__NR_setgid),DENY(__NR_setresuid),DENY(__NR_setresgid),DENY(__NR_setns),DENY(__NR_unshare),DENY(__NR_clone),DENY(__NR_clone3),DENY(__NR_fork),DENY(__NR_vfork),
 BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog p={sizeof(filter)/sizeof(filter[0]),filter};
 struct rlimit core={0,0};
 if(setrlimit(RLIMIT_CORE,&core)<0||prctl(PR_SET_DUMPABLE,0)<0||mlockall(MCL_CURRENT|MCL_FUTURE)<0)return -1;
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0)return -1;
 return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}
/* Explicit child-side jail provisioning BEFORE UID drop and credential birth.
 * Only inherited directory descriptors and literal destinations are accepted.
 * Caller must already own a fresh CLONE_NEWNS|CLONE_NEWNET namespace; compare
 * against parent namespace inode to prevent privatizing the supervisor itself.
 * No network device is created: fresh netns has only down loopback by default.
 */
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdio.h>
static int p4_bind_directory(int fd,const char *target,int readonly){
 struct stat s;char source[64];
 if(fstat(fd,&s)<0||!S_ISDIR(s.st_mode)){errno=EINVAL;return -1;}
 if(snprintf(source,sizeof(source),"/proc/self/fd/%d",fd)>=(int)sizeof(source)){errno=EINVAL;return -1;}
 if(mkdir(target,0700)<0&&errno!=EEXIST)return -1;
 struct stat dest;
 if(lstat(target,&dest)<0||!S_ISDIR(dest.st_mode)||dest.st_uid!=0||(dest.st_mode&0022)){errno=EPERM;return -1;}
 if(mount(source,target,NULL,MS_BIND|MS_REC,NULL)<0)return -1;
 /* Recursive mount attributes avoid writable nested submount escape. Kernel
  * without mount_setattr is rejected, never silently downgraded. */
 struct mount_attr attrs={0};
 attrs.attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC|(readonly?MOUNT_ATTR_RDONLY:0);
 if(syscall(SYS_mount_setattr,AT_FDCWD,target,AT_RECURSIVE,&attrs,sizeof(attrs))<0)return -1;
 return 0;
}
int p4_provision_jail(int jail_fd,int source_fd,int fixture_fd,int evidence_fd,
                     unsigned long parent_mount_inode,unsigned long parent_net_inode){
 struct stat m,n,j;
 if(geteuid()!=0||fstat(jail_fd,&j)<0||!S_ISDIR(j.st_mode)||j.st_uid!=0||(j.st_mode&0022)||!(j.st_mode&0001)){errno=EPERM;return -1;}
 if(stat("/proc/self/ns/mnt",&m)<0||stat("/proc/self/ns/net",&n)<0)return -1;
 if((unsigned long)m.st_ino==parent_mount_inode||(unsigned long)n.st_ino==parent_net_inode){errno=EPERM;return -1;}
 if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)<0)return -1;
 if(fchdir(jail_fd)<0)return -1;
 if(p4_bind_directory(source_fd,"source",1)<0||p4_bind_directory(fixture_fd,"fixture",1)<0||p4_bind_directory(evidence_fd,"evidence-store",0)<0)return -1;
 /* Failures terminate this disposable namespace; never continue after partial
  * mount setup. Host-side pidfd/cgroup cleanup retains evidence directory. */
 if(chroot(".")<0||chdir("/")<0)return -1;
 return 0;
}

/* Fixed file mounts, never caller-controlled destination paths. Called while
 * still privileged inside fresh namespaces, before chroot/UID/key issuance. */
static int bind_file_fd(int fd,const char *target,int executable,int device){
 struct stat s;char src[64];
 if(fstat(fd,&s)<0)return -1;
 if((!device&&!S_ISREG(s.st_mode))||(device&&(!S_ISCHR(s.st_mode)||major(s.st_rdev)!=10||minor(s.st_rdev)!=232))){errno=EINVAL;return -1;}
 if(!device&&immutable_fd(fd)<0)return -1;
 int file=open(target,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
 if(file<0)return -1;
 close(file);
 if(snprintf(src,sizeof(src),"/proc/self/fd/%d",fd)>=(int)sizeof(src)){errno=EINVAL;return -1;}
 if(mount(src,target,NULL,MS_BIND,NULL)<0)return -1;
 struct mount_attr attrs={0};
 attrs.attr_set=MOUNT_ATTR_NOSUID|(!device?MOUNT_ATTR_NODEV|MOUNT_ATTR_RDONLY:0)|(!executable?MOUNT_ATTR_NOEXEC:0);
 return syscall(SYS_mount_setattr,AT_FDCWD,target,0,&attrs,sizeof(attrs));
}
static int p4_provision_vm_assets(int firecracker_fd,int kernel_fd,int rootfs_fd,int kvm_fd){
 if(geteuid()!=0){errno=EPERM;return -1;}
 /* mount propagation already made private by this namespace before assets. */
 if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)<0)return -1;
 if(mkdir("dev",0755)<0&&errno!=EEXIST)return -1;
 struct stat dir;
 if(lstat("dev",&dir)<0||!S_ISDIR(dir.st_mode)||dir.st_uid!=0||(dir.st_mode&0022)){errno=EPERM;return -1;}
 if(bind_file_fd(firecracker_fd,"firecracker",1,0)<0||bind_file_fd(kernel_fd,"kernel",0,0)<0||bind_file_fd(rootfs_fd,"rootfs",0,0)<0||bind_file_fd(kvm_fd,"dev/kvm",0,1)<0)return -1;
 if(mkdir("proc",0755)<0&&errno!=EEXIST)return -1;
 if(lstat("proc",&dir)<0||!S_ISDIR(dir.st_mode)||dir.st_uid!=0||(dir.st_mode&0022)){errno=EPERM;return -1;}
 return mount("proc","proc","proc",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL);
}

static int p4_bind_evidence_volume(int fd,int readonly){
 struct stat st;char src[64];
 if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)){errno=EINVAL;return -1;}
 if(readonly&&immutable_fd(fd)<0)return -1;
 int dest=open("evidence",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
 if(dest<0)return -1;
 close(dest);
 if(snprintf(src,sizeof(src),"/proc/self/fd/%d",fd)>=(int)sizeof(src)){errno=EINVAL;return -1;}
 if(mount(src,"evidence",NULL,MS_BIND,NULL)<0)return -1;
 struct mount_attr attrs={0};attrs.attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC|(readonly?MOUNT_ATTR_RDONLY:0);
 return syscall(SYS_mount_setattr,AT_FDCWD,"evidence",0,&attrs,sizeof(attrs));
}
