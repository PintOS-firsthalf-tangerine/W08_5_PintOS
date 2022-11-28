-m #include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* 첫번째 공백 전까지의 문자열 파싱 */
	char *parsed_file_name, *save_ptr;
	parsed_file_name = strtok_r (file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	printf("===> parsed_file_name : %s\n", parsed_file_name);
	tid = thread_create (parsed_file_name, PRI_DEFAULT, initd, fn_copy);	// thread를 만들고 tid 반환, 스레드 종료된 거 아님
	
	// // sema down
	// struct thread* child_thread = get_child_process(tid);
	// sema_down(&child_thread->load_sema);

	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();  

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {	
	// child 스레드를 만들어 놓고, 이 스레드가 CPU를 할당받으면 
	// kernel_thread()함수 안에 있는 __do_fork를 통해 fork를 진행하도록 세팅해주는 함수이다. 
	/* Clone current thread to new thread.*/

	// if를 따로 저장해서 do_fork에 가져다 써야 한다. 
	

	tid_t child_tid;
	printf("===> 2 :: process_fork doing\n");
	child_tid = thread_create (name,

	gistruct thread *curr = thread_current();
	curr->parent_if_ = if_;

	tid_t child_tid = thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());	// 여기의 curr는 parent(User)스레드임
	
	struct thread *child = get_child_process(child_tid);
	sema_down(&child->fork_sema);

	if(child->exit_status == -1)	// 커널에서 종료된 경우 
	{
		return TID_ERROR;
	}

	return child_tid;
}

struct thread *get_child_process(int pid) {
	/* 자식 리스트에 접근하여 프로세스 디스크립터 검색 */ 
	struct thread *curr = thread_current();
	struct list_elem *temp_elem = list_begin(&curr->child_list);
	
	for(; temp_elem != list_tail(&curr->child_list); temp_elem = temp_elem->next) {
		struct thread *temp_thread = list_entry(temp_elem, struct thread, child_elem);
		if (temp_thread->tid == pid) {
			/* 해당 pid가 존재하면 프로세스 디스크립터 반환 */ 
			return temp_thread;
		}
	}

	/* 리스트에 존재하지 않으면 NULL 리턴 */
	return NULL;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* 부모 스레드의 주소 공간(페이지)을 새로 만든 공간(페이지)에 그대로 복제
*/
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {	// pte-> parent의 pte, va->새로만든주소, aux->parent
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;
	
	//--------------project2-system_call-start---------------

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))	
		return true;			
	/* 2. Resolve VA from the parent's page map level 4. */
	if((parent_page = pml4_get_page (parent->pml4, va)) == NULL){
		return false;
	}
	
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	// int newpage_size = palloc_init();	// 반환값 있음, 일단 넘어간다 ?????
	if((newpage = palloc_get_page(PAL_USER | PAL_ZERO)) == NULL){	// 왜 PAL_ZERO 넣어야하지?????

		return false;
	}
	
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);	// duplicate parent's page
	writable = is_writable(pte); //
	
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {	// child 스레드는 인터럽트를 enable하고, 이 함수를 실행하고, 종료된다
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;	//	부모 스레드(USER)
	struct thread *current = thread_current ();		//	자식 스레드(현재 스레드)(USER)
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = parent->parent_if_;
	bool succ = true;


	if_.R.rax = 0;



	//--------------project2-system_call-start---------------

	// 부모의 유저스택 레지스터 정보(parent_if_)를 저장
	// clone all the value of the registers
	// printf("do_fork의 memcpy 바로 전, intr_frame의 size: %d\n", sizeof(struct intr_frame));
	// memcpy(parent_if, current->parent_if_, sizeof(struct intr_frame));
	// printf("do_fork의 memcpy 후\n");

	// printf("parent_if 값 넣어주기 전\n");
	// parent_if = current->parent_if_;
	// memcpy(parent_if, current->parent_if_, sizeof(struct intr_frame));
	// printf("parent_if 값 넣어준 후\n");

	//--------------project2-system_call-end-----------------

	/* 1. Read the cpu context to local stack. */
	// cpu context: parent_if, local stack: &if_
	// printf("if memcpy로 값 넣어주기 전\n");
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	// printf("if memcpy로 값 넣어준 후\n");

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();	// 자식 스레드의 pml4에 커널용 pml4를 넣어줌
	if (current->pml4 == NULL)
		goto error;

	// (context switch를 위해) 커널용 pml4와 커널용 stack pointer를 자식 스레드(current)에 세팅해 줌
	process_activate (current);	
	
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	// duplicate_pte() 실행
	//-> 부모 스레드의 주소 공간(페이지)을 새로 만든 공간(페이지)(자식용)에 그대로 복제
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)){	
		goto error;
		}

#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`	-> file은 디스크에 있기 때문
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	// 부모와 연결된 파일들을 자식하고도 연결시킴
	
	current->fdt[0] = parent->fdt[0];	// STDIN
	current->fdt[1] = parent->fdt[1];	// STDOUT
	int fd_int;
	for (fd_int=2; fd_int<parent->next_fd; fd_int++)
	{
		current->fdt[fd_int] = file_duplicate(parent->fdt[fd_int]);	
	}
	current->next_fd = parent->next_fd;

	if_.R.rax = 0;	// 자식 프로세스의 return value를 0으로 설정

	// 자식 프로세스를 초기화?
	process_init ();	// 없어도 됨

	// 자식이 부모를 복제해야하기 때문에 복제를 완료하기 전까지 부모를 살려둔다. 
	// -> 부모는 세마 다운 함, 자식은 복제 다했으면 세마 업 함
	// 부모는 세마 다운 된 상태로 기다리고 있음 -> 다른 곳에서 wait()로 부모가 기다리도록 함
	
	// 자식의 fork_sema를 세마 업
	sema_up(&current->fork_sema);

	/* Finally, switch to the newly created process. */ // -> new process가 자식임
	if (succ)
		do_iret (&if_);
	
error:
	current->exit_status = TID_ERROR;
	// 세마 업
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	//thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	/* 실행 중인 프로세스의 레지스터 정보, 스택 포인터, instruction count를
	 * 저장하는 자료구조 */ 
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);
	
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
	sema_up(&thread_current()->load_sema);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);	// ??????? 분석은 나중에
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {

	// child_tid를 이용해서 자식 스레드 찾기 
	struct thread *child_thread = get_child_process(child_tid);

	// 예외처리 발생 시 -1 리턴
	if (child_thread == NULL)
	{
		return -1;
	}

	// wait for child. sema down.
	sema_down(&child_thread->wait_sema);
	int child_exit_status = child_thread->exit_status;
	list_remove(&child_thread->child_elem);
	sema_up(&child_thread->free_sema);

	// If pid did not call exit(), 
	// but was terminated by the kernel 
	// (e.g. killed due to an exception), 
	// wait(pid) must return -1

	return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// %s: full name passed to fork()
	// no print when kernel thread that is not a user process terminates // ??????
	// printf("%s: exit(%d)\n", curr->name, );

	sema_up(&curr->wait_sema);
	sema_down(&curr->free_sema);
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the next thread.
 * This function is called on every context switch. */
/* (context switch를 위해) 커널용 pml4와 커널용 stack pointer를 세팅해 줌
*/
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();	// 페이지 디렉토리 생성
	if (t->pml4 == NULL)
		goto done;

	// 레지스터 값을 실행 중인 스레드의 페이지 테이블 주소로 변경
	process_activate (thread_current ());	// 페이지 테이블 활성화

	//----------project2-userprogram-start--------------------------
	
	/* 인자들을 띄어쓰기 기준으로 토큰화 및 토큰의 개수 계산 (strtok_r() 함수 이용) */

	/* Argument Parsing 구현*/
	char *arg[128];
	int argc = 0;
	argument_parsing(file_name, arg, &argc);

	file_name = arg[0];

	//----------project2-userprogram-end----------------------------

	/* Open executable file. */
	file = filesys_open (file_name);	// 프로그램 파일 Open
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	// ELF 파일의 헤더 정보를 읽어와서 &ehdr에 저장
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	// 버퍼(&ehdr)에서 배치 정보를 읽어와서 &phdr에 저장
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					// 배치정보를 통해 파일을 메모리에 적재
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	// 스택을 초기화
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */	

	argument_stack(arg, argc, &if_->rsp);	// 아무거나 될 수 있는 자료형에 &if_->rsp(아무나의 주소)를 넣는다.

	// 레지스터 R의 rdi, rsi에 각각 argc와 return address(fake address)를 넣는다.
	if_->R.rdi = argc;	// argc
	if_->R.rsi = if_->rsp + 8;
	// printf("if_->R.rdi %d\n", if_->R.rdi);
	// printf("if_->R.rsi %p\n", if_->R.rsi);
	// hex_dump(if_->rsp, if_->rsp, USER_STACK - if_->rsp, true);
	success = true;
	printf ("===>load success\n");


done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);

	// sema_up();
	return success;
}

/*
file_name을 파싱해서 argv에 넣어줌. 파싱 개수는 argc에 저장.
*/
void argument_parsing(const char *file_name, char **argv, int *argc)
{	
	char *token, *save_ptr;

	/* argv
	0 - name
	1 - 1st arg
	2 - 2nd arg
	...
	*/
	for(token = strtok_r (file_name, " ", &save_ptr); token != NULL;
		token = strtok_r (NULL, " ", &save_ptr), (*argc)++)
			argv[*argc] = token;
}

/*
parsing한 결과인 argv(프로그램명과 인자들)를 스택에 push한다.
*/
void argument_stack(char **argv, int argc, void **rsp)
{
	size_t str_l;

	str_l = 0;
	int temp_argc = argc - 1;
	int lens = 0;

	char* address_argv[128];
	for(; temp_argc >= 0; temp_argc--)
	{	
		str_l = strlen(argv[temp_argc]) + 1;
		lens += str_l;
		*rsp -= str_l;

		address_argv[temp_argc] = *rsp;
		memcpy(*rsp, argv[temp_argc], str_l);
	}

	// padding 확인 - 들어가는 값은 (uint8_t)0 
	int padding = 8 - lens%8;
	if (lens%8 != 0)
	{
		*rsp -= padding;
		memset(*rsp, (uint8_t)0, padding);
	}

	// temp_argc 자리에다가 (void *)0 센티넬(널 포인터)
	*rsp -= 8;
	memset(*rsp, NULL, 8);
	int *temp_rsp;

	// temp_argc개수 만큼 주소들 넣어줌.
	for (int j=argc-1; j>=0; j--)
	{
		*rsp -= 8;
		temp_rsp = *rsp;
		*temp_rsp = address_argv[j];
	}

	// return address
	*rsp -= 8;
	memset(*rsp, NULL, 8);
	// printf("argc: %d\n", argc);
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
