#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include <stddef.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/filesys/filesys.h"
#include "include/threads/synch.h"
#include "include/filesys/file.h"
#include "include/devices/input.h"	
#include "include/lib/kernel/console.h"
#include "include/userprog/process.h"

// pid 자료형 추가
/* Process identifier. */
typedef int pid_t;
struct lock filesys_lock;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct intr_frame *if_);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void syscall_init (void);


#define PID_ERROR ((pid_t) -1)
#endif /* userprog/syscall.h */

