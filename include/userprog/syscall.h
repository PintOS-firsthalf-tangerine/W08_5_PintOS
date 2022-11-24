#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);

// pid 자료형 추가
/* Process identifier. */
typedef int pid_t;

struct lock filesys_lock;

#define PID_ERROR ((pid_t) -1)
#endif /* userprog/syscall.h */
