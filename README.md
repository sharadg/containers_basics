# Basics of container runtime

## In Unix, typical processes are created using fork and exec model

For example, look at [fork_and_exec.c](fork_exec/fork_and_exec.c)

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

Here you can see that  ially our program `fork_and_exec` is created with a PID of 2620 but it's itself fork'd and exec'd by the shell, it's ParentPID 24882 is that of the shell from previous output. It creates a fork's child with PID of 2621 and then, waits for child to finish before returning back to shell.

## Introducing namespaces

Linux glibc provides `fork()` as a wrapper around `clone()` system call. So, in effect, we can substitute `clone()` in this example with no change in functionality. This is what we are going to next. We have created a simple function in [ns_child_exec.c](pid_namespace/ns_child_exec.c) which lets us supply various flags to create multiple different namespaces and run an arbitrary command inside the newly created namespace(s).

```
cd ../pid_namespace/
make
./bin/ns_child_exec -h
./bin/ns_child_exec: invalid option -- 'h'
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