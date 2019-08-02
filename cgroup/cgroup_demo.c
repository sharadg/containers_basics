#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <string.h>

/* A simple error-handling function: print an error message based
   on the value in 'errno' and terminate the calling process */

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)


int
main(int argc, char *argv[])
{
  int i;
  char* ptr;
  i = 0;
  
  while(i < 50) {
    if ((ptr = (char *) malloc(1<<20)) == NULL) { /* 1MB allocated */
      errExit("Allocation failed");
    }

    memset(ptr, 0, (1<<20));
    printf("Allocated %d MB\n", i+1);
    i++;
  }
  
  printf("Finished allocation\n");
  return 0;
}
