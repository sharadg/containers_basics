# Basics of container runtime

## Unix fork and exec model

In Unix, typically new processes are created using fork and exec model. For example, look at [fork_and_exec.c](fork_exec/fork_and_exec.c)

```
cd fork_exec/

make

echo $$
24882
```

You first confirm the process id of the shell you are running in. And, then. 

```
./bin/fork_and_exec echo hello world

Parent (PID=2620) created child with PID 2621
Parent (PID=2620; PPID=24882) waiting on it's child

Child  (PID=2621) exists with parent PID=2620
hello world
```

Here you can see that initially our program `fork_and_exec` is created with a PID of `2620` but it's itself fork'd and exec'd by the shell, it's Parent PID `24882` is that of the shell from previous output. It creates a fork's child with PID of `2621` and then, waits for child to finish before returning back to shell.

## Introducing namespaces

A  namespace  wraps  a global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource.  Changes to the global resource are visible to other processes that are members of the namespace, but are invisible to other processes.  One use of namespaces is to implement containers.

       Linux provides the following namespaces:

       Namespace   Constant          Isolates
       Cgroup      CLONE_NEWCGROUP   Cgroup root directory
       IPC         CLONE_NEWIPC      System V IPC, POSIX message queues
       Network     CLONE_NEWNET      Network devices, stacks, ports, etc.
       Mount       CLONE_NEWNS       Mount points
       PID         CLONE_NEWPID      Process IDs
       User        CLONE_NEWUSER     User and group IDs
       UTS         CLONE_NEWUTS      Hostname and NIS domain name

Linux glibc provides `fork()` as a wrapper around `clone()` system call. So, in effect, we can substitute `clone()` in our previous example with no change in functionality. This is what we are going to next. We have created a simple function in [ns_child_exec.c](pid_namespace/ns_child_exec.c) which lets us supply various flags to create multiple different namespaces and run an arbitrary command inside the newly created namespace(s).

```
cd ../pid_namespace/

make

./bin/ns_child_exec -h

Usage: ./bin/ns_child_exec [options] cmd [arg...]
Options can be:
    -i   new IPC namespace
    -m   new mount namespace
    -n   new network namespace
    -p   new PID namespace
    -u   new UTS namespace
    -U   new user namespace
    -v   Display verbose messages
```

### PID namespace

We are going to use this utility to run our `fork_and_exec` program inside a new `PID` namespace (by passing `-p` flag, `-v` for verbose output).

```
# cd back into fork_exec folder
cd -

# In order to create new namespaces, we need admin privileges

sudo ../pid_namespace/bin/ns_child_exec -vp ./bin/fork_and_exec echo hello world
../pid_namespace/bin/ns_child_exec [PID: 6357]: PID of child created by clone() is 6358
Parent (PID=1) created child with PID 2
Parent (PID=1; PPID=0) waiting on it's child

Child  (PID=2) exists with parent PID=1
hello world
../pid_namespace/bin/ns_child_exec: terminating
```

So, we have 3 generations of processes now.

```
Global namespace: 
ns_child_exec [PID 6357]    -> fork_and_exec [PID 6358, PPID 6357]

New namespace: 
                            -> fork_and_exec [PID 1, PPID 0] -> echo [PID 2, PPID 1]
```

So, even though `fork_and_exec` program has a PID 6358 in the global PID namespace, but it starts off with PID 1 in the newly created PID namespace.

### UTS Namespace

We can similarly pass a different flag `-u` to create a new UTS namespace and see how we can change the hostname of the process inside the container without changing the hostname on the parent/global namespace

```
# create a new UTS namespace and execute bash shell inside it

sudo ../pid_namespace/bin/ns_child_exec -u bash

# current hostname (inherited from global namespace)
hostname
sharadg-mint

# change to a new value and look it up again
hostname dummy-container

hostname
dummy-container

# exit out of container
exit

# lookup the hostname in the global namespace
hostname
sharadg-mint
```

### Network, Mount, User namespaces

Combining all these namespaces, plus PID and UTS namespaces is what ultimately you can use to isolate your processes in sandboxes, called "containers". Even though there is no such terminology for containers inside Linux kernel, but using these constructs in addition to cgroups and chroot/pivot_root system calls, you can create enough of an abstraction that you can collectively call the sandboxed process a container. But, before we create our own containers, let's briefly discuss cgroups.

## cgroups - Isolate and manage resources

(This section is derived from article [chroot, cgroups and namespaces — An overview](https://itnext.io/chroot-cgroups-and-namespaces-an-overview-37124d995e3d)).

Control groups(cgroups) is a Linux kernel feature which limits, isolates and measures resource usage of a group of processes. Resources quotas for memory, CPU, network and IO can be set. These were made part of Linux kernel in Linux 2.6.24.

```
# Use cgcreate, cgexec and cgdelete to create, use and delete cgroup controllers

sudo cgcreate -g memory:myapp_mem

# change to root
sudo -i

# cd to cgroup folder that we just created
cd /sys/fs/cgroup/memory/myapp_mem/

# disable swapping
echo 0 > memory.swappiness

# set memory limit (bytes)
echo 5242880 > memory.limit_in_bytes

# read it back to confirm
cat memory.limit_in_bytes 
5242880

cat memory.swappiness 
0
```

Without setting any cgroup limits, we can run our sample program [cgroup_demo.c](cgroup/cgroup_demo.c) and notice that it's able to allocate 50 MB memory.

```
./bin/cgroup_demo 
Allocated 0 MB
Allocated 1 MB
Allocated 2 MB
Allocated 3 MB
...
Allocated 46 MB
Allocated 47 MB
Allocated 48 MB
Allocated 49 MB
Finished allocation
```

Now, we run it inside our newly created cgroup `myapp_mem` after setting up memory constraints on the cgroup.

```
sudo cgexec -g memory:myapp_mem ./bin/cgroup_demo 
Allocated 1 MB
Allocated 2 MB
Allocated 3 MB
Allocated 4 MB
Killed

# delete the cgroup once done
sudo cgdelete -g memory:myapp_mem
```


# Next up - chroot, veth pairs and root filesystem

Now, that we understand how namespaces lets our processes run in their own little sandboxes, next we are going to look into how to make these sandboxes into cages where we can put more deterministic boundaries on them in terms of resource constraints (CPU, Memory) and that they cannot get out of (encapsulating in their own root disk).


## Start off with a rootfs

We can use [debootstrap](https://wiki.debian.org/Debootstrap) to create a container rootfs from scratch or we can cheat by running a docker image and exporting the image from resulting container for faster iteration.

```
# we will start off with a base docker image of ubuntu:18.04
# and then install few utilities on top of that image

docker run -it ubuntu:18.04 /bin/bash

root@3124a4d24703:/# apt-get update -y && apt-get install less jq net-tools iputils-ping iproute2 netcat nano telnet

...

# exit out of the container

root@3124a4d24703:/# exit
exit
```

Next up, take a `docker export` of the stopped container that we will use as our root filesystem

```
# Look for container id
docker ps -a
CONTAINER ID        IMAGE                      COMMAND                  CREATED             STATUS                     PORTS               NAMES
3124a4d24703        ubuntu:18.04               "/bin/bash"              6 minutes ago       Exited (0) 4 seconds ago                       distracted_einstein

# take an export
docker export 3124a4d24703 > rootfs.tar

# make a local folder and untar the contents
mkdir rootfs
tar xvf rootfs.tar -C ./rootfs

```

## Mount namespaces, procfs, pivot_root, chroot

We are going to use a Linux utility `unshare` which lets us run any program in different namespace(s). We will illustrate what it means to run in separate user, mount or network namespaces on our way to get a first class container working.

```
unshare -h

Usage:
 unshare [options] [<program> [<argument>...]]

Run a program with some namespaces unshared from the parent.

Options:
 -m, --mount[=<file>]      unshare mounts namespace
 -u, --uts[=<file>]        unshare UTS namespace (hostname etc)
 -i, --ipc[=<file>]        unshare System V IPC namespace
 -n, --net[=<file>]        unshare network namespace
 -p, --pid[=<file>]        unshare pid namespace
 -U, --user[=<file>]       unshare user namespace
 -C, --cgroup[=<file>]     unshare cgroup namespace
 -f, --fork                fork before launching <program>
     --mount-proc[=<dir>]  mount proc filesystem first (implies --mount)
 -r, --map-root-user       map current user to root (implies --user)
     --propagation slave|shared|private|unchanged
                           modify mount propagation in mount namespace
 -s, --setgroups allow|deny  control the setgroups syscall in user namespaces

 -h, --help                display this help
 -V, --version             display version

For more details see unshare(1).
```

As you notice, we will be passing different options to get a feel for remaining namespaces.


- PID and Mount namspaces

If we go back to PID namesapces for a second, and run the following command 

```
# You need root privilege to create new namespaces with unshare. 
# Also, here we create a new PID namespace (-p) and also have unshare fork itself (-f) before create a child process with clone (to run chroot inside that child)
sudo unshare -p -f chroot rootfs/ /bin/bash
root@sharadg-mint:/# echo $$
1
```

We can see that our shell has PID of 1 in the new namespace but if we execute `ps -eflx` in this shell, we notice something troubling

```
ps -eflx
F   UID   PID  PPID PRI  NI    VSZ   RSS WCHAN  STAT TTY        TIME COMMAND
4     0  9154  5838  20   0  84056  4840 poll_s S    ?          0:00 sudo unshare -p -f chroot rootfs/ /bin/bash LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;0
4     0  9155  9154  20   0   7456   756 wait   S    ?          0:00  \_ unshare -p -f chroot rootfs/ /bin/bash LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01
4     0  9156  9155  20   0  18508  3408 wait   S    ?          0:00      \_ /bin/bash LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:
4     0  9964  9156  20   0  26248  2624 -      R+   ?          0:00          \_ ps -eflx LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;
...
4     0  5622     1  20   0 366600 13372 poll_s Ssl  ?          0:00 /usr/lib/packagekit/packagekitd LANG=en_US.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=
4     0  3676     1  20   0 632484 16464 poll_s Ssl  ?          0:00 /usr/sbin/NetworkManager --no-daemon LANG=en_US.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
...
```

That, in fact, we can see the entire process tree from the parent (global) namespace. It's because of the fact that utilities such as `ps` relies on process data read for `proc` psuedo filesystem, typically mounted at `/proc`. In order to hide our parent process data, we need to do 2 things: create a new mount namespace, and then re-mount `procfs` at `/proc` which will only expose process data from our current PID namspace. Like so,

```
# Unshare allows us to do both of these steps by letting us specify --mount-proc option

sudo unshare -p  -f --mount-proc=./rootfs/proc chroot rootfs/ /bin/bash
root@sharadg-mint:/# echo $$
1
root@sharadg-mint:/# ps -efl 
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 -  4627 wait   06:05 ?        00:00:00 /bin/bash
0 R root         5     1  0  80   0 -  8600 -      06:06 ?        00:00:00 ps -efl
root@sharadg-mint:/# 

# if unshare complains about mounting ./rootfs/proc as procfs, then you may need to run the following once before running the above command

sudo mount -t proc proc ./rootfs/proc/
```

This will be our main sequence of activities while creating our own container runtime - create a new mount namespace, `pivot_root` or `chroot` to a new rootfs, mount procfs at `/proc' before `cloning` the process that will run in our newly created container.


## Containter networking (veth pairs)

Please see a very good explanation of [container networking using veth pairs](http://tejom.github.io/c/linux/containers/docker/networking/2016/10/08/containers-from-scratch-pt2-networking.html)


## Combining everything into a running container