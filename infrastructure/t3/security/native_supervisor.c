/* Library only: NO CLI, socket enrollment, commands or research authority.
 * Caller is privileged pinned supervisor holding owner-verified immutable FDs.
 * Spawn returns a stopped child and a birth-created pidfd, never PID lookup.
 */
#define _GNU_SOURCE
#include <linux/sched.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <grp.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
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
struct p4_child { pid_t pid; int pidfd; int resume_fd; int error_fd; };
static int immutable_fd(int fd) {
 struct statvfs v; unsigned int flags=0;
 if(fstatvfs(fd,&v)<0) return -1;
 if(v.f_flag & ST_RDONLY) return 0;
 if(ioctl(fd,FS_IOC_GETFLAGS,&flags)==0 && (flags & (FS_IMMUTABLE_FL|FS_VERITY_FL))) return 0;
 errno=EPERM;return -1;
}
int p4_spawn_role_paused(int exe_fd,int job_cgroup_fd,uid_t uid,gid_t gid,
                    int bootstrap_fd,int role,int channel_in,int channel_out,struct p4_child *out) {
 int target_fd=role==1?198:role==2?199:200;
 if(role<1||role>3||(role==2&&(channel_in<0||channel_out<0))){errno=EINVAL;return -1;}
 int sync[2],err[2],pidfd=-1;
 if(!out||uid==0||gid==0||exe_fd==196||exe_fd==197||exe_fd==198||exe_fd==199||exe_fd==200||immutable_fd(exe_fd)<0){errno=EPERM;return -1;}
 if(pipe2(sync,O_CLOEXEC)<0)return -1;
 if(pipe2(err,O_CLOEXEC)<0){close(sync[0]);close(sync[1]);return -1;}
 struct clone_args args={0};args.flags=CLONE_PIDFD|CLONE_INTO_CGROUP|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS;
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
  int saved_in=-1,saved_out=-1;
  if(role==2){saved_in=fcntl(channel_in,F_DUPFD_CLOEXEC,256);saved_out=fcntl(channel_out,F_DUPFD_CLOEXEC,256);if(saved_in<0||saved_out<0)_exit(127);channel_in=saved_in;channel_out=saved_out;}
  char go;
  if(read(sync[0],&go,1)!=1||go!='R')_exit(126);
  close(sync[0]);
  /* Bootstrap already parent-created; all other descriptors closed. */
  if(dup2(bootstrap_fd,target_fd)<0)goto fail;
  if(fcntl(target_fd,F_SETFD,0)<0)goto fail;
  if(role==2){
   if(dup2(channel_in,196)<0||dup2(channel_out,197)<0||fcntl(196,F_SETFD,0)<0||fcntl(197,F_SETFD,0)<0)goto fail;
  }
  int keep[5]={target_fd,exe_fd,err[1],196,197};int count=role==2?5:3;
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
