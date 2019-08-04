/* main.c
   Create a basic container that executes a given command in new namespace(s)
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
const char *hostname = "inside_container";

static void usage(char *pname) {
    fprintf(stderr, "Usage: %s [options] cmd [arg...]\n", pname);
    fprintf(stderr, "Options can be:\n");
    exit(EXIT_FAILURE);
}

//wrapper for pivot root syscall
int pivot_root(char *a, char *b) {
    if (mount(a, a, "bind", MS_BIND | MS_REC, "") < 0) {
        errExit("error mount");
    }
//    if (mkdir(b, 0755) < 0) {
//        errExit("error mkdir");
//    }
    printf("pivot setup ok\n");

    return syscall(SYS_pivot_root, a, b);
}

/* sync primitive */
int checkpoint[2];

void rand_char(char *str, int size) {
    char new[size];
    for (int i = 0; i < size; i++) {
        new[i] = 'A' + (rand() % 26);
    }
    new[size] = '\0';
    strncpy(str, new, size);
    return;
}

int create_peer() {
    char *id = (char *) malloc(4);
    char *set_int;
    char *set_int_up;
    char *add_to_bridge;

    rand_char(id, 4);
    printf("id is %s\n", id);
    asprintf(&set_int, "ip link add veth%s type veth peer name veth1", id);
    system(set_int);
    asprintf(&set_int_up, "ip link set veth%s up", id);
    system(set_int_up);
    asprintf(&add_to_bridge, "ip link set veth%s master %s", id, BRIDGE);
    system(add_to_bridge);

    free(id);
    return 0;
}

int network_setup(pid_t pid) {
    char *set_pid_ns;
    asprintf(&set_pid_ns, "ip link set veth1 netns %d", pid);
    system(set_pid_ns);
    return 0;
}

/* Update the mapping file 'map_file', with the value provided in
   'mapping', a string that defines a UID or GID mapping. A UID or
   GID mapping consists of one or more newline-delimited records
   of the form:

       ID_inside-ns    ID-outside-ns   length

   Requiring the user to supply a string that contains newlines is
   of course inconvenient for command-line use. Thus, we permit the
   use of commas to delimit records in this string, and replace them
   with newlines before writing the string to the file. */

static void update_map(char *mapping, char *map_file) {
    int fd, j;
    size_t map_len;     /* Length of 'mapping' */

    /* Replace commas in mapping string with newlines */

    map_len = strlen(mapping);
    for (j = 0; j < map_len; j++)
        if (mapping[j] == ',')
            mapping[j] = '\n';

    fd = open(map_file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "open %s: %s\n", map_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (write(fd, mapping, map_len) != map_len) {
        fprintf(stderr, "write %s: %s\n", map_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(fd);
}

/* Linux 3.19 made a change in the handling of setgroups(2) and the
   'gid_map' file to address a security issue. The issue allowed
   *unprivileged* users to employ user namespaces in order to drop
   The upshot of the 3.19 changes is that in order to update the
   'gid_maps' file, use of the setgroups() system call in this
   user namespace must first be disabled by writing "deny" to one of
   the /proc/PID/setgroups files for this namespace.  That is the
   purpose of the following function. */

static void proc_setgroups_write(pid_t child_pid, char *str) {
    char setgroups_path[PATH_MAX];
    int fd;

    snprintf(setgroups_path, PATH_MAX, "/proc/%ld/setgroups",
             (long) child_pid);

    fd = open(setgroups_path, O_RDWR);
    if (fd == -1) {

        /* We may be on a system that doesn't support
           /proc/PID/setgroups. In that case, the file won't exist,
           and the system won't impose the restrictions that Linux 3.19
           added. That's fine: we don't need to do anything in order
           to permit 'gid_map' to be updated.

           However, if the error from open() was something other than
           the ENOENT error that is expected for that case,  let the
           user know. */

        if (errno != ENOENT)
            fprintf(stderr, "ERROR: open %s: %s\n", setgroups_path,
                    strerror(errno));
        return;
    }

    if (write(fd, str, strlen(str)) == -1)
        fprintf(stderr, "ERROR: write %s: %s\n", setgroups_path,
                strerror(errno));

    close(fd);
}

/* Start function for cloned child */
static int childFunc(void *arg) {
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

    if (sethostname(hostname, strlen(hostname)) == -1)
        errExit("sethostname");

    /* Retrieve and display hostname */

    if (uname(&uts) == -1)
        errExit("uname");
    printf("[In child namespace] uts.nodename in child:  %s\n", uts.nodename);

    /* set various mount points and network interfaces */

//    if (unshare(CLONE_NEWNS) < 0)
//        errExit("unshare issue");
//    if (umount2("/proc", MNT_DETACH) < 0)
//        errExit("error unmount");

    if (pivot_root("./rootfs", "./rootfs/.old") < 0) {
        errExit("error pivot");
    }
//    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, NULL);
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        errExit("error mounting new procfs");
//    mount("t", "/sys", "sysfs", 0, NULL);
    chdir("/"); //change to root dir, man page for pivot_root suggests this
    if (umount2("/.old", MNT_DETACH) < 0)
        errExit("error unmount old");

//    if (rmdir("/.old") < 0) {
//        errExit("error rmdir");
//    }

    system("ip link set veth1 up");

    char *ip_cmd;
    asprintf(&ip_cmd, "ip addr add %s/24 dev veth1", argv[0]);
    system(ip_cmd);
    system("ip route add default via 10.240.0.1 dev veth1");

    execvp(argv[1], &argv[1]);
    errExit("execvp");
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];    /* Space for child's stack */

int main(int argc, char *argv[]) {
    pid_t child_pid;
    char *uid_map, *gid_map;
    const int MAP_BUF_SIZE = 100;
    char map_buf[MAP_BUF_SIZE];
    char map_path[PATH_MAX];

    srand(time(0));

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

//    system("mount --make-rprivate  /");
    printf("[In main namespace] starting...\n");
    create_peer();

    child_pid = clone(childFunc, child_stack + STACK_SIZE,
                      SIGCHLD | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWUSER,
                      &argv[1]);
    if (child_pid == -1)
        errExit("clone");

    printf("[In main namespace] %s: PID of child created by clone() is %ld\n",
           argv[0], (long) child_pid);

    /* Parent falls through to here */
    /* Update the UID and GID maps in the child */

    snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", (long) child_pid);
    snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long) getuid());
    uid_map = map_buf;
    update_map(uid_map, map_path);

    proc_setgroups_write(child_pid, "deny");

    snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", (long) child_pid);
    snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1", (long) getgid());
    gid_map = map_buf;
    update_map(gid_map, map_path);

    /* assign child container's veth interface to newly created network namespace */
    network_setup(child_pid);

    /* Close the write end of the pipe, to signal to the child that we
   have updated the UID and GID maps */

    close(checkpoint[1]);


    if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
        errExit("waitpid");

    printf("[In main namespace] %s: terminating\n", argv[0]);
    exit(EXIT_SUCCESS);
}
