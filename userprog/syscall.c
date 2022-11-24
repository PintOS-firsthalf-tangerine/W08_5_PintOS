#include "userprog/syscall.h"
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

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
int write(int fd, const void *buffer, unsigned size);
void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&filesys_lock);
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	// Make system call handler call system call using system call number
	switch (f->R.rax)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
	}

	// Check validation of the pointers in the parameter list.
	// check_address()
	check_address(f->rsp);

	// Copy arguments on the user stack to the kernel.
	// get_argument(f->rsp, f->R.rsi, f->R.rdi);

	// Save return value of system call at rax register.
}

int write(int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
}

void check_address(void *addr) {
	if (addr == NULL){	//Null 포인터가 아니어야 함
		// printf("=======check1\n");
		exit(-1);
	}
		
	if (!is_user_vaddr(addr)) { // 커널 가상 주소 공간에 대한 포인터가 아니어야 함
		// printf("=======check2\n");
		exit(-1);
	}

	if(pml4_get_page(thread_current()->pml4, addr ) == NULL) {// 매핑되지 않은 가상 메모리에 대한 포인터가 아니어야 함
		// printf("=======check3\n");
		exit(-1);
	}
} 

// void get_argument(void *rsp, int *argv, int argc) {
	
// 	void **addr;

// 	// argc 개수 만큼 주소가 저장된 곳을 체크하는데, 걔네들이 유저 영역인지 확인.

// 	// 유저 스택에 저장된 인자값들을 커널로 저장
// 	// rsp를 8씩 올리면서 인자값들을 argv에 저장
// 	addr = rsp + 8;
// 	for(int i = 0; i < argc; i++, argv++, addr += 8){
// 		// 유저 스택에서 주소를 저장하고 있는 곳의 유효성 검사
// 		// check_address(addr);

// 		// 인자가 저장된 위치가 유저 영역인지 확인
// 		// argv에 저장된 인자값들이 유저 영역인지 확인
// 		check_address(*addr);
// 		*argv = *addr;
// 	}
// }

// Shutdown pintos
void halt() {
	power_off();
	// Use void power_off(void) in include/threads/init.h
}

// Exit process
void exit(int status) {

	printf("%s: exit(%d)\n",thread_current()->name, status);
	// Use void thread_exit(void)
	thread_exit();

	// It should print message “Name of process: exit(status)”.
}

int exec(const char *cmd_line) {
	// Create child process and execute program corresponds to cmd_line on it
}

int wait(pid_t pid) {
	// Wait for termination of child process whose process id is pid

}

bool create (const char *file, unsigned initial_size) {
	// 파일을 생성하는 시스템 콜
	// 성공 일 경우 true, 실패 일 경우 false 리턴 
	// file:생성할 파일의 이름및경로정보 
	// initial_size : 생성할 파일의 크기
	check_address(file);

	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	// 파일을 삭제하는 시스템 콜 
	// file:제거할 파일의이름및경로정보 
	// 성공 일 경우 true, 실패 일 경우 false 리턴
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file){
	check_address(file);

	int fd = -1;	// fd값을 -1로 초기화 -> open이 안되면 -1을 반환해야 함

	if (filesys_open(file)) {	// open이 되면 if문 들어감

		lock_acquire(&filesys_lock);	// filesys_lock을 획득
		fd = thread_current()->next_fd++;	// next_fd를 반환하도록 하고, 다음 fd를 위해 1을 더해줌
		if (fd >= 64)					// fd의 max 크기가 64임
			fd = -1;
		lock_release(&filesys_lock);	// filesys_lock release
	}

	return fd;
}
