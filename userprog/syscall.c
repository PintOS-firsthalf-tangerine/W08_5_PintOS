#include "userprog/syscall.h"
#include "include/threads/palloc.h"

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
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
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
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
	}

	// Check validation of the pointers in the parameter list.
	// check_address()
	check_address(f->rsp);

	// Copy arguments on the user stack to the kernel.
	// get_argument(f->rsp, f->R.rsi, f->R.rdi);

	// Save return value of system call at rax register.
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
	thread_current()->exit_status = status;

	// Use void thread_exit(void)
	thread_exit();

	// It should print message “Name of process: exit(status)”.
}

pid_t fork (const char *thread_name, struct intr_frame *if_) {
	
	// 시스템콜이 받은 인자 if_ -> 즉, 커널 스택에 있는 if_를 받아온다
	/*
		- if
		커널 스택에 있는 'if'는 같은 스레드(스레드A) 내에서 유저모드->커널모드 Context Switching이 일어날 때, 
		유저모드가 사용하던 레지스터 정보를 저장한 곳이다. 

		- tf
		반대로 커널 영역의 Struct thread 내부에 있는 'tf'는 
		다른 스레드와 Context Switching이 일어날 때(스레드A->스레드B) 
		사용하던 레지스터 정보(유저모드, 커널모드 상관 없음)를 저장한 곳이다. 
	*/
	return process_fork(thread_name, if_);
}

int wait(pid_t pid) {
	// Wait for termination of child process whose process id is pid

	//?????? wait하는동안 interrupt disable해야하나?
	return process_wait(pid);
}

int exec(const char *cmd_line) {
	// Create child process and execute program corresponds to cmd_line on it
	// thread_create(cmd_line, PRI_DEFAULT, process_exec, cmd_line);
	// tid 받았으니깐, 이걸로 process_exec의 반환값이 있으면 그걸 반환함

	check_address(cmd_line);
	// FILE_NAME을 복사하기 위한 작업 - process_create_initd() 참고
	int size = strlen(cmd_line) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if ((fn_copy) == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, cmd_line, size);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();

	// return process_create_initd(cmd_line);
}

bool remove (const char *file) {
	// 파일을 삭제하는 시스템 콜 
	// file:제거할 파일의이름및경로정보 
	// 성공 일 경우 true, 실패 일 경우 false 리턴
	check_address(file);
	return filesys_remove(file);
}

bool create (const char *file, unsigned initial_size) {
	// 파일을 생성하는 시스템 콜
	// 성공 일 경우 true, 실패 일 경우 false 리턴 
	// file:생성할 파일의 이름및경로정보 
	// initial_size : 생성할 파일의 크기
	check_address(file);

	return filesys_create(file, initial_size);
}

int open (const char *file){
	check_address(file);
	struct file *open_file;

	int fd = -1;	// fd값을 -1로 초기화 -> open이 안되면 -1을 반환해야 함

	if ((open_file = filesys_open(file)) != NULL) {	// open이 되면 if문 들어감

		lock_acquire(&filesys_lock);	// filesys_lock을 획득
		fd = thread_current()->next_fd++;	// next_fd를 반환하도록 하고, 다음 fd를 위해 1을 더해줌
		thread_current()->fdt[fd] = open_file;	// fdt[fd]에 file 넣기
		if (fd >= 64)					// fd의 max 크기가 64임
			fd = -1;
		lock_release(&filesys_lock);	// filesys_lock release
	}

	return fd;
}

int filesize (int fd){	// 파일의 길이를 반환
	
	if(!(2 <= fd && fd < 64))
		return -1;
	
	struct file *curr_file = thread_current()->fdt[fd];
	if (curr_file == NULL)
			return -1;
	// lock_acquire(&filesys_lock);	// filesys_lock을 획득
	off_t file_size_result = file_length(thread_current()->fdt[fd]);
	// lock_release(&filesys_lock);	// filesys_lock release
	return file_size_result;
}

int read (int fd, void *buffer, unsigned size){
	if (fd == 0){
		int cnt = 0;
		while(1){	// size만큼 받았거나, '\n'이 오면 끝
			if (cnt >= size) {	// size만큼 받은 경우
					break;
			}
			cnt++;

			char key = input_getc();
			if (key == '\n') {	// '\n'이 온 경우
				char *buffer = key;
				break;
			}
		
			char *buffer = key;
			buffer++; 
		} 
	}
	else if(2 <= fd < 64){
		struct file *curr_file = thread_current()->fdt[fd];
		if (curr_file == NULL)
			return -1;

		lock_acquire(&filesys_lock);	// lock 걸기
		off_t read_result = file_read(curr_file, buffer, size);
		lock_release(&filesys_lock);	// lock 풀기
		return read_result;
	}
	else {
		return -1;
	}
}

int write(int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	else if (2 <= fd < 64) {
		struct file *curr_file = thread_current()->fdt[fd];
		if (curr_file == NULL)
			return -1;
		lock_acquire(&filesys_lock);	// lock 걸기
		off_t write_result = file_write(curr_file, buffer, size);
		lock_release(&filesys_lock);	// lock 풀기
		return write_result;
	}
	else {
		return -1;
	}
}

void seek (int fd, unsigned position) {
	if (2 <= fd < 64) {
		struct file *curr_file = thread_current()->fdt[fd];
		if (curr_file == NULL)
			return;
		// lock_acquire(&filesys_lock);	// lock 걸기
		file_seek(curr_file, position);
		// lock_release(&filesys_lock);	// lock 풀기
	}
}

unsigned tell (int fd) {
	if (2 <= fd < 64) {
		struct file *curr_file = thread_current()->fdt[fd];
		if (curr_file == NULL)
			return -1;
		// lock_acquire(&filesys_lock);	// lock 걸기
		off_t tell_result = file_tell(curr_file);
		// lock_release(&filesys_lock);	// lock 풀기
		return tell_result;
	}
	else {
		return -1;
	}
}

void close (int fd) {
	if (2 <= fd < 64) {
		struct file *curr_file = thread_current()->fdt[fd];
		if (curr_file == NULL)
			return;

		// lock_acquire(&filesys_lock);	// lock 걸기
		file_close(curr_file);
		// lock_release(&filesys_lock);	// lock 풀기

		thread_current()->fdt[fd] = NULL;
	}
}