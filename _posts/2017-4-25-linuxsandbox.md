---
layout: post
title: linux中的容器与沙箱初探
categories: [Sandbox]
description: linux中的容器与沙箱初探
keywords: Sandbox, Linux
---

# linux中的容器与沙箱初探

## linux中的沙箱技术

### 文件系统隔离

#### chroot jail

通常来说，提到chroot一般有两个含义，chroot(1)是/usr/bin/chroot, chroot(2)是glibc中的一个函数。

>chroot(1)<br>
>chroot - run command or interactive shell with special root directory<br>
>chroot [OPTION] NEWROOT [COMMAND [ARG]...]

>chroot(2)<br>
>chroot - change root directory<br>
>int chroot(const char *path);

chroot的主要功能就是改变根目录，如运行chroot "/home/atum/newroot/" 会启动一个新的shell，且目录"/home/atum/newroot/"成为该shell下的新的根目录"/"。

chroot沙箱可以将进程对文件的访问限制在一个指定的目录中，但是由于chroot不是一个安全的feature，所以该沙箱可能会被逃逸出来。关于chroot沙箱逃逸的方法[在这里](https://github.com/earthquake/chw00t)

#### restricted bash

rbash的主要作用是限制了部分bash命令，其作用之一就是使得bash只能执行当前目录下的可执行文件，且不允许改变当前工作目录。

>If bash is started with the name rbash, or the -r option is supplied at invocation, the shell becomes restricted.  A restricted shell  is  used to  set  up an environment more controlled than the standard shell.

```
atum@ubuntu:~$ rbash
atum@ubuntu:~$ cd PWN
rbash: cd: restricted
atum@ubuntu:~$ ./PWN/rp++
rbash: ./PWN/rp++: restricted: cannot specify `/' in command names
atum@ubuntu:~$ export PATH=$PATH:/home/atum/PWN
rbash: PATH: readonly variable

```
rbash的绕过方法也有很多，通常跟chroot配合使用

### 进程监控

#### ptrace

ptrace是一个系统调用，tracer进程可以使用ptrace监控和修改tracee进程的运行状态，如内存、寄存器的值等。

>long ptrace(enum __ptrace_request request, pid_t pid,void *addr, void *data);

>The ptrace() system call provides a means by which one process (the "tracer") may observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers. 

使用ptrace可以让某一进程处于受控状态，所以可以用作实现沙箱，如我们可以利用ptrace来监控tracee使用哪些系统调用，并组织tracee使用某些危险的系统调用等。

#### seccomp

seccomp是linux提供的一种沙箱机制，可以用来限制程序可以使用和不可使用的系统调用

>seccomp (short for secure computing mode) is a computer security facility in the Linux kernel. seccomp allows a process to make a one-way transition into a "secure" state where it can only make user configured system calls 

seccomp沙箱主要有两种模式，SECCOMP\_SET\_MODE\_STRICT只运行调用4个系统调用read(2), write(2), _exit(2), sigreturn(2)四个系统调用，而SECCOMP\_SET\_MODE\_FILTER则允许通过BPF指定系统调用的黑名单或者白名单

>SECCOMP\_SET\_MODE\_STRICT<br>              
>The only system calls that the calling thread is permitted to make are read(2), write(2), _exit(2) (but not exit_group(2)), and sigreturn(2).

>SECCOMP\_SET\_MODE\_FILTER<br>
>The system calls allowed are defined by a pointer to a Berkeley Packet Filter (BPF) passed via args.

seccomp本身是一种很安全的技术，但是在SECCOMP\_SET\_MODE\_FILTER环境下通常会因为BPF使用不正确导致沙箱存在被绕过的可能。

## linux中的容器技术

### 容器：
>operating-system-level virtualization is a server virtualization method in which the kernel of an operating system allows the existence of multiple isolated user-space instances, instead of just one. Such instances, which are sometimes called containers, software containers

容器的目的是进行**资源隔离**和**控制隔离**。

* 资源隔离：隔离计算资源，如CPU、RAM、DISK等。
* 控制隔离：隔离一些控制结构，如UID、PID等

### **Cgroup**与**Namespace**：

**资源隔离**依赖于linux内核的Cgroup实现，**控制隔离**依赖于linux内核的namespace

>The Linux kernel provides the cgroups functionality that allows limitation and prioritization of resources (CPU, memory, block I/O, network, etc.) without the need for starting any virtual machines, and also namespace isolation functionality that allows complete isolation of an applications' view of the operating environment, including process trees, networking, user IDs and mounted file systems.


目前比较有名的容器均是基于Cgroup和namespace实现的：

* LXC:
>LXC combines the kernel's cgroups and support for isolated namespaces to provide an isolated environment for applications

* Docker 
>Docker containers are very similar to LXC containers, and they have similar security features. When you start a container with docker run, behind the scenes Docker creates a set of namespaces and control groups for the container.

### 使用**Namespace**

linux中的namespace思想上跟C++里面的差不多，通俗来说把一些全局的东西分割成很多份局部，而且使得处在局部里面的人以为自己是全局。 

>A namespace wraps a global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource.  Changes to theg lobal resource are visible to other processes that are members of the namespace, but are invisible to other processes.  One use of namespaces is to implement containers.
       
目前最新版的linuxkernel支持7个命名空间
       
```
Linux provides the following namespaces:

Namespace   Constant          Isolates
Cgroup      CLONE_NEWCGROUP   Cgroup root directory
IPC         CLONE_NEWIPC      System V IPC, POSIX message queues
Network     CLONE_NEWNET      Network devices, stacks, ports, etc.
Mount       CLONE_NEWNS       Mount points
PID         CLONE_NEWPID      Process IDs
User        CLONE_NEWUSER     User and group IDs
UTS         CLONE_NEWUTS      Hostname and NIS domain nam

```
#### 命名空间相关的API以及用法示例：
**clone**：
创建一个新进程，并且可以根据flag创建新的命名空间。新创建的进程是该命名空间的owner

```C
int clone(int (*fn)(void *), void *child_stack,int flags, void *arg, ...)

Example:

#define _GNU_SOURCE
#include <sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int childFunc(char * str){
	printf("%s: My pid is %d\n",str,getpid());
	sleep(1000);
}
#define STACK_SIZE (1024 * 1024)
int main(int argc,char* argv[]){
	void *stack = malloc(STACK_SIZE);
	stackTop = stack + STACK_SIZE; 
	printf("parent: My pid is %d\n",getpid());
	int pid = clone(childFunc, stackTop, CLONE_NEWPID | SIGCHLD, "child");
	wait(NULL);
	printf("parent: My child pid is %d\n",pid);
}

run it, we get:
parent: My pid is 12424
child: My pid is 0
parent: My child pid is 12425

```

**setns** 让当前进程加入一个已存在的命名空间。命名空间由fd指定，命名空间类型由nstype指定。

```C
 int setns(int fd, int nstype);
 
 Example：
 
 #define _GNU_SOURCE
 #include <sys/wait.h>
 #include <sched.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 int main(int argc, char *argv[]){
	
	int fd;
	printf("before: my pid is %d",getpid());
	fd = open("/proc/12425/ns/pid", O_RDONLY);  
	setns(fd, CLONE_NEWPID);
	printf("after: my pid is %d",getpid());
  }
  
  run it, we get:
  before: my pid is 12426
  after: my pid is 2

```

**unshare** 让当前进程离开当前的命名空间，然后创建并进入一个新的命名空间, 效果跟clone差不多，只不过unshare不会创建新的进程。

```
int unshare(int flags);

#define _GNU_SOURCE
#include <sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char *argv[]){
	printf("before: my pid is %d",getpid());
	unshare(CLONE_NEWPID);
	printf("before: my pid is %d",getpid());
}

run it we get:

before: my pid is 12427
after: my pid is 1
```
以上案例主要是以PID NAMESPACE为例，可以看得出PID NAMESPACE可以做到PID的隔离，其他NAMESPACE的用法类似，如USER NAMESPACE可以做到UID和GID的隔离，MOUNT NAMESPACE可以做到文件系统的隔离等。

另外，创建除了USER NAMESPACE以外的NAMESPACE需要root权限，所以通常的做法是首先进入USER NAMESPACE，这样就可以得到一个当前USER NAMESPACE下的root user，再创建其他的namespace
> A process created via fork(2) or clone(2) without the CLONE\_NEWUSER flag is a member of the same user namespace as its parent

> A call to clone(2) or unshare(2) with the CLONE\_NEWUSER flag makes the new child process (for clone(2)) or the caller (for unshare(2)) a member of the new user namespace created by the call

### 使用**Cgroup**

Cgroup用来限制和监控进程对资源的使用
>Control cgroups, usually referred to as cgroups, are a Linux kernel feature which allow processes to be organized into hierarchical groups whose usage of various types of resources can then be limited and monitored.

#### 使用Cgroup限制资源（以CPU为例）：

```bash
挂载指定cgroup
mount -t cgroup -o cpu,cpuacct none /sys/fs/cgroup/cpu,cpuacct
或者可以挂载所有cgroup
mount -t cgroup -o all cgroup /sys/fs/cgroup


查看已挂载的cgroup：
# ls /sys/fs/cgroup
blkio    cpu,cpuacct  freezer  net_cls           perf_event
cpu      cpuset       hugetlb  net_cls,net_prio  pids
cpuacct  devices      memory   net_prio          systemd

创建一个新的cpu cgroup， 并设置该cgroup的进程最多使用50%的CPU
# mkdir /sys/fs/cgroup/cpu/cg1
# 

运行一个耗时间的脚本
#!/bin/sh
i=0;
while true;
do i=$i+1;
done;

查看CPU的使用
# top
   PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND    
  4145 root      20   0   21404   4544   2776 R 100.0  0.1   0:25.62 bash 
  
将当前4145进程加入cgroup 
echo 4145 > /sys/fs/cgroup/cpu/cg1/tasks

再次查看CPU的使用
# top
   PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND    
  4145 root      20   0   30576   4696   2136 R  49.5  0.1   0:55.41 bash      
```

cgroup以进程族(process group)为单位进行资源的限制，fork产生的子进程会继承父进程的cgroup。

>A child process created via fork(2) inherits its parent's cgroup memberships.  A process's cgroup memberships are preserved across execve(2).

另外，我们也可以使用setrlimit prlimit等系统调用来以单个用户或者单个进程为单位进行资源的限制，这两套资源限制的机制是独立生效的
