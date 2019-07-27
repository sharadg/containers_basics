/* ns_child_exec.c

   Copyright 2013, Michael Kerrisk
   Licensed under GNU General Public License v2 or later

   Create a child process that executes a shell command in new namespace(s)
   as well as mount a separate proc filesystem
*/
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

/* A simple error-handling function: print an error message based
   on the value in 'errno' and terminate the calling process */

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

#define BRIDGE "cni0"
const char *hostname = "container01";
const char *domainname = "container";

static void
usage(char *pname)
{
    fprintf(stderr, "Usage: %s [options] cmd [arg...]\n", pname);
    fprintf(stderr, "Options can be:\n");
    exit(EXIT_FAILURE);
}

//wrapper for pivot root syscall
int pivot_root(char *a, char *b) {
  if (mount(a, a, "bind", MS_BIND | MS_REC,"")<0){
    errExit("error mount");
  }
  if (mkdir(b, 0755) <0){
    errExit("error mkdir");
  }
  printf("pivot setup ok\n");
  
  return syscall(SYS_pivot_root,a,b);
}

/* sync primitive */
int checkpoint[2];

void rand_char(char *str,int size) {
  char new[size];
  for(int i=0;i<size;i++){
    new[i] = 'A' + (rand() % 26);
  }
  new[size] = '\0';
  strncpy(str,new,size);
  return;
}

int create_peer() {
  char *id = (char*) malloc(4);
  char *set_int;
  char *set_int_up;
  char *add_to_bridge;
  
  rand_char(id, 4);
  printf("id is %s\n", id);
  asprintf(&set_int,"ip link add veth%s type veth peer name veth1", id);
  system(set_int);
  asprintf(&set_int_up,"ip link set veth%s up", id);
  system(set_int_up);
  asprintf(&add_to_bridge,"ip link set veth%s master %s", id, BRIDGE);
  system(add_to_bridge);
  
  free(id);
  return 0;
}

int network_setup(pid_t pid) {
  char *set_pid_ns;
  asprintf(&set_pid_ns,"ip link set veth1 netns %d",pid);
  system(set_pid_ns);
  return 0;
}

static int              /* Start function for cloned child */
childFunc(void *arg)
{
    char ch;
    char **argv = arg;

    /* Wait until the parent has updated the UID and GID mappings. See
       the comment in main(). We wait for end of file on a pipe that will
       be closed by the parent process once it has updated the mappings. */

    close(checkpoint[1]);    /* Close our descriptor for the write end
                                   of the pipe so that we see EOF when
                                   parent closes its descriptor */
    if (read(checkpoint[0], &ch, 1) != 0) {
        fprintf(stderr, "Failure in child: read from pipe returned != 0\n");
        exit(EXIT_FAILURE);
    }

    printf("[In child namespace] childFunc(): PID  = %ld\n", (long) getpid());
    printf("[In child namespace] childFunc(): PPID = %ld\n", (long) getppid());

    struct utsname uts;

    /* Change hostname in UTS namespace of child */

    if (sethostname("inside_container", strlen("inside_container")) == -1)
        errExit("sethostname");

    /* Retrieve and display hostname */

    if (uname(&uts) == -1)
        errExit("uname");
    printf("[In child namespace] uts.nodename in child:  %s\n", uts.nodename);

    /* set various mount points and network interfaces */
    
    if (unshare(CLONE_NEWNS) <0)
      errExit("unshare issue");
    if (umount2("/proc", MNT_DETACH) <0)
      errExit("error unmount");
    if (pivot_root("./rootfs","./rootfs/.old")<0){
      errExit("error pivot");
    }
    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, NULL);
    if (mount("proc", "/proc", "proc", 0, NULL) <0)
      errExit("error proc mount");
    mount("t", "/sys", "sysfs", 0, NULL);
    
    chdir("/"); //change to root dir, man page for pivot_root suggests this
    if (umount2("/.old", MNT_DETACH) < 0)
      errExit("error unmount old");
    
    system("ip link set veth1 up");
    
    char *ip_cmd;
    asprintf(&ip_cmd,"ip addr add %s/24 dev veth1", argv[0]);
    system(ip_cmd);
    system("ip route add default via 10.240.0.1 dev veth1");	
    
    execvp(argv[1], &argv[1]);
    errExit("execvp");
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];    /* Space for child's stack */

int
main(int argc, char *argv[])
{
    int flags, opt, verbose;
    pid_t child_pid;
    char uid_map[9], gid_map[9];    
    char map_path[PATH_MAX];
    srand(time(0));
    
    flags = 0;
    verbose = 0;

    /* Parse command-line options. The initial '+' character in
       the final getopt() argument prevents GNU-style permutation
       of command-line options. That's useful, since sometimes
       the 'command' to be executed by this program itself
       has command-line options. We don't want getopt() to treat
       those as options to this program. */


    if (argc < 2) {
      usage(argv[0]);
    }

    /* We use a pipe to synchronize the parent and child, in order to
       ensure that the parent sets the UID and GID maps before the child
       calls execve(). This ensures that the child maintains its
       capabilities during the execve() in the common case where we
       want to map the child's effective user ID to 0 in the new user
       namespace. Without this synchronization, the child would lose
       its capabilities if it performed an execve() with nonzero
       user IDs (see the capabilities(7) man page for details of the
       transformation of a process's capabilities during execve()). */

    if (pipe(checkpoint) == -1)
        errExit("pipe");


    system("mount --make-rprivate  /");
    printf("[In main namespace] starting...\n");
    create_peer();
    
    child_pid = clone(childFunc,child_stack + STACK_SIZE,
                      SIGCHLD | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET, &argv[1]);
    if (child_pid == -1)
        errExit("clone");

    printf("[In main namespace] %s: PID of child created by clone() is %ld\n",
           argv[0], (long) child_pid);

    /* Parent falls through to here */

    /* Close the write end of the pipe, to signal to the child that we
       have updated the UID and GID maps */

    close(checkpoint[1]);

    /* assign child container's veth interface to newly created network namespace */
    network_setup(child_pid);

    if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
        errExit("waitpid");

    printf("[In main namespace] %s: terminating\n", argv[0]);
    exit(EXIT_SUCCESS);
}
