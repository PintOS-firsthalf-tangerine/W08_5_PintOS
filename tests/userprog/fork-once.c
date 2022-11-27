/* Forks and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int pid;

  pid = fork("child");
  printf("===>pid : %d\n", pid);
  if ((pid)){
    printf("===> before waiting\n");
    printf("===> I am parent\n");
    //int status = wait (pid);
    //msg ("Parent: child exit status is %d", status);
  } else {
    msg ("child run");
    exit(81);
  }
}
