/* ns_run.c

   Copyright 2013, Michael Kerrisk
   Licensed under GNU General Public License v2 or later

   This program is similar is a simple demonstration
   of fork and exec functionality.
*/
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

/* A simple error-handling function: print an error message based
   on the value in 'errno' and terminate the calling process */

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static void
usage(char *pname)
{
    fprintf(stderr, "Usage: %s cmd [arg...]\n", pname);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    int fd, opt;
    pid_t pid;

    if (argc <= optind)
        usage(argv[0]);

    pid = fork();
    if (pid == -1)
      errExit("fork");
    
    if (pid != 0) {                 /* Parent */
      printf("Grand-Parent\n--(PID=%ld)\n",
             (long) getppid());
      printf("Parent\n----(PID=%ld) created\nChild\n------(PID=%ld)\n",
             (long) getpid(), (long) pid);
      printf("(((( Parent waiting on it's child ))))\n");
      
      if (waitpid(-1, NULL, 0) == -1)     /* Wait for child */
        errExit("waitpid");
      exit(EXIT_SUCCESS);
    }

    /* Child falls through to code below */
    
    printf("\nChild (PID=%ld) exists with Parent (PID=%ld)\n.....\n",
           (long) getpid(), (long) getppid());
    
    sleep(3);
    execvp(argv[optind], &argv[optind]);
    errExit("execvp");
}
