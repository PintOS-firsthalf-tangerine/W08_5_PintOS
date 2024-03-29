#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct thread *idle_thread;

//--------------project1-alarm-start--------------

// THREAD_BLOCKED 상태의 스레드를 관리하기 위한 리스트 자료 구조 추가 >> Sleep_queue
static struct list sleep_list;

/* 
next_tick_to_awake: sleep_list에 있는 모든 스레드들의 wakeup_tick값 중 최소값
>> list_entry를 통해 다음에 깨울 스레드 무엇인지 알 수 있음 
*/
int64_t next_tick_to_awake = INT64_MAX;

//--------------project1-alarm-end----------------

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;


/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */ // time quantum: 40ms
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
/* 스택 포인터는 running 스레드가 사용한 스택의 크기만큼 증가한다. 
   running 스레드가 변경되면, 스택 포인터를 초기화시켜주어야 하므로
   스택 포인터를 page 크기를 기준으로 '내림'처리하여 초기화한다.*/
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

//--------------project1-alarm-start--------------

/*
 * next_tick_to_awake 업데이트하는 함수
*/
void update_next_tick_to_awake(int64_t ticks)
{
	if(next_tick_to_awake > ticks)	 
		next_tick_to_awake = ticks;			
}

/*
 * next_tick_to_awake를 반환
*/
int64_t get_next_tick_to_awake(void)
{
	return next_tick_to_awake;
}

/*
	현재 Running 스레드를 Blocked 상태로 만들고 sleep queue에 삽입한 뒤, 
	다음 스레드를 Running 상태로 만듦.
	만약 현재 Running 스레드가 이미 종료되었다면, destruction_req에 삽입함
*/
void thread_sleep(int64_t ticks)
{
	// Thread를 blocked 상태로 만들고 sleep queue에 삽입하여 대기

	// 현재(running) 스레드 선언 및 초기화
	struct thread *curr = running_thread();

	// 깨어나야 할 ticks(잠자는 시간)를 저장할 변수
	int64_t awake_ticks;

	// old_level에 이전 interrupt에 대한 정보 저장하고 interrupt를 disable 시킴
	enum intr_level old_level = intr_disable ();

	// 현재 스레드가 idle 스레드가 아닐 경우
	if(curr != idle_thread)
	{	
		// 현재 스레드에 잠자야 할 시간(깨어나야 할 시간) 즉 ticks를 저장
		curr->wakeup_tick = ticks;

		// Sleep list에 현재 스레드 삽입하고
		list_push_back(&sleep_list, &curr->elem);
	
		// idle스레드만 있을 떄, next_tick_to_awake 업데이트 해줌
		update_next_tick_to_awake(ticks);

		// destruction_req(list 자료형)를 모두 비워주고 
		// 현재 스레드의 상태를 BLOCKED로 바꾸고, 
		// 스케쥴 실행 - next 스레드 상태를 RUNNING으로 변경, curr 스레드를 destruction_req에 넣음 
		do_schedule (THREAD_BLOCKED);	
	}

	intr_set_level (old_level);	// interrupt를 다시 허용
}


// thread.c 함수에 매개변수로 들어오는 ticks는 '시각'이고, 
// 	timer.c에서의 ticks는 '시간'이다.

/*
  sleep list의 모든 스레드들을 순회하면서
  만약 깨워야 할 스레드들이 있다면, 해당 스레드를 sleep list에서 제거하고 ready list에 넣는다. 
	next_tick_to_awake 값을 깨우지 않는 나머지 스레드의 wake_up_tick 중 최솟값으로 갱신한다. 
*/
void thread_awake(int64_t ticks)
{	
	// sleep list 순회
	struct list_elem *traverse_list_elem = list_begin(&sleep_list);
	struct thread *traverse_thread;
	next_tick_to_awake = INT64_MAX;	// 매 순회하기 전마다 최솟값을 INT64_MAX로 갱신
	while(traverse_list_elem != list_end(&sleep_list))
	{
		traverse_thread = list_entry(traverse_list_elem, struct thread, elem);
		if(traverse_thread->wakeup_tick <= ticks)
		{	// 스레드의 tick값이 인자로 받은 ticks보다 작거나 같은 경우
			// 해당 스레드를 sleeplist에서 제거하고
			// unblock: 해당 스레드를 readylist에 넣고, 상태를 READY로 변경
			traverse_list_elem = list_remove(&traverse_thread->elem);
			thread_unblock(traverse_thread);
		}
		else {// remove하지 않는 경우에는, 스레드들 중에서 최솟값을 갱신해야 함
			traverse_list_elem = list_next(traverse_list_elem);
			update_next_tick_to_awake(traverse_thread->wakeup_tick);
		}
	}

}
//--------------project1-alarm-end-----------------


/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);



	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the global thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	

	//--------------project1-alarm-start---------------

	// Sleep queue 자료구조 초기화 코드 추가
	list_init (&sleep_list);

	//--------------project1-alarm-end-----------------

	//--------------project2-system_call-start---------------
	// all list 초기화
	list_init(&all_list);
	//--------------project2-system_call-end-----------------

	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);

	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	// thread_create ("idle", PRI_MIN, idle, &idle_started);

	//--------------project1-priority_scheduling-start---------------

	thread_create ("idle", PRI_DEFAULT, idle, &idle_started);

	//--------------project1-priority_scheduling-end-----------------

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
/* 타이머 인터럽트 핸들러에 의해 매 timer tick마다 호출되는 함수 
   idle, kernel, user ticks를 셈
*/
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;	// 자식 스레드 틀
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);	// 새로 만든 스레드(자식 스레드)
	tid = t->tid = allocate_tid ();

	// 자식스레드의 parent멤버에 부모스레드 저장
	t->parent = thread_current();

	/* 프로그램이 로드되지 않음 */
	t->is_load = false;	///???? sungtae

	/* 프로세스가 종료되지 않음 */
	t->is_process_alive = true;	// ????? sungtae

	// 부모스레드의 자식리스트에 t 추가
	list_push_back(&thread_current()->child_list, &t->child_elem);

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;	// 이 함수에서 dofork() 실행 됨
	t->tf.R.rdi = (uint64_t) function;	// __do_fork()
	t->tf.R.rsi = (uint64_t) aux;		// thread_current() -> 부모가 될 스레드, process_fork()에서 호출됨
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;
	// t->fdt[0] = stdin;
	// t->fdt = palloc_get_multiple(PAL_ZERO, 1);


	/* Add to run queue. */
	thread_unblock (t);	// t를 ready_list의 우선순위 순으로 삽입
	// 예시: t가 curr보다 우선순위가 높다면 t는 ready_list의 맨 앞에 삽입됨

	//--------------project1-priority_scheduling-start---------------

	struct thread *curr = thread_current ();

	// 생성된 스레드의 우선순위가 현재 실행 중인 스레드의 우선순위보다 높다면, CPU를 양보한다. 
	if (t->priority > curr->priority) {
		thread_yield();	// 여기서 cpu 양보
	}

	//--------------project1-priority_scheduling-end-----------------

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
/*
  매개변수로 받은 스레드를 우선순위 순으로 readylist에 넣고 상태를 READY로 변경
*/
void
thread_unblock (struct thread *t) {

	//--------------project1-priority_scheduling-start---------------

	// 기존 코드
	/*
	enum intr_level old_level;
	ASSERT (is_thread (t));
	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_push_back (&ready_list, &t->elem); 
	t->status = THREAD_READY;
	intr_set_level (old_level);
	*/

	enum intr_level old_level;

	ASSERT (is_thread (t));
	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	
	// ready list에 elem을 우선순위 순으로 넣어준다. 
	// (ready_list는 이미 정렬된 상태) -> 새로운 스레드를 매번 우선순위 순으로 넣어주기 때문
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, 0); // 
	t->status = THREAD_READY;
	intr_set_level (old_level);

	//--------------project1-priority_scheduling-end-----------------
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	list_remove(&thread_current()->all_list_elem);
	thread_current()->is_process_alive = 0;
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
/*
현재 thread가 CPU를 양보하여 ready_list에 삽입될 때, 우선순위 순서로 정렬되어 삽입하고, 
do_schedule()을 호출하여  현재 스레드상태를 READY로, 다음 스레드상태를 RUNNING으로 변경
*/
void
thread_yield (void) {

	//--------------project1-priority_scheduling-start---------------

	// 현재 thread가 CPU를 양보하여 ready_list에 삽입될 때, 
	// 우선순위 순서로 정렬되어 삽입되도록 수정

	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	// old_level에 기존 작업에 대한 정보 저장하고 interrupt를 disable 시킴
	// 이전 interrupt 상태를 old level에 저장.
	old_level = intr_disable ();

	//  current thread가 idle_thread가 아니면 ready list에 curr_elem넣기
	if (curr != idle_thread)
	{
		// list_push_back (&ready_list, &curr->elem); // 기존 코드 - ready_list의 맨 뒤에 현재 elem를 넣어줌.
		list_insert_ordered(&ready_list, &curr->elem, cmp_priority, 0); // priority-scheduling
	}

	//--------------project1-priority_scheduling-end-----------------

	// 현재 스레드를 READY상태로 변경하고, 다음 스레드를 RUNNING상태로 변경
	do_schedule (THREAD_READY);	

	intr_set_level (old_level);

}

//--------------project1-priority_scheduling-start---------------

/* Sets the current thread's priority to NEW_PRIORITY. */
/*   
   현재 스레드의 우선순위를 변경하고, test_max_priority를 호출한다. 
*/
void
thread_set_priority (int new_priority) {
	
	//--------------project1_3-priority_donation-start---------------

	thread_current ()->init_priority = new_priority;

	// thread_current ()->priority = new_priority;

	// 우선순위를 변경으로 인한 donation 관련 정보를 갱신한다. 
	refresh_priority();
	
	donate_priority();

	test_max_priority();
}

/*
  현재 스레드의 우선순위가 ready_list의 가장 높은 우선순위보다 낮으면, 
  thread_yield()를 호출하여, 현재 스레드를 ready_list에 넣는다.
  (현재 스레드의 우선순위가 더 높다면 계속 실행)
*/
void test_max_priority(void)
{

	// ready_list가 비어있다면 test_max_priority 실행하지 않음
	if(list_empty(&ready_list))
		return;

	if(cmp_priority(list_front(&ready_list), &thread_current()->elem, 0))
	{
		// yield를 호출하여 현재 스레드를 READY로 만들고, ready_list에 넣는다.
		thread_yield();
	}
	
}

/*
  a스레드의 우선순위가 b스레드의 우선순위보다 높으면 true(1), 아니면 false(0) 반환
*/
bool cmp_priority(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED)
{
	// list_insert_ordered() 함수에서 사용하기 위해, 정렬 방법을 결정하기 위한 함수를 작성
	// elem 선언 안해도 들어가는 이유 
	// -> struct thread는 전역변수로 선언(thread.h에)되어 있으므로, 그 멤버인 elem을 사용 가능
	return list_entry(a, struct thread, elem)->priority > list_entry(b, struct thread, elem)->priority;
}

//--------------project1_2-priority_scheduling-end-----------------

//--------------project1_3-priority_donation-start---------------

bool thread_compare_donate_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	return list_entry(a, struct thread, donation_elem)->priority > list_entry(b, struct thread, donation_elem)->priority;
}

/* 
   lock을 차지하고 있거나 기다리고 있는 스레드들에게 우선순위를 donate 함.
 */
void donate_priority(void)
{
	struct thread *temp = thread_current();
	struct thread *temp_lock_holder;
	int nested_depth = 0;

	// lock을 기다리고 있는 스레드가 있다면, 모두 순회하면서 우선순위를 donate
	while((temp->wait_on_lock != NULL) && (nested_depth < 8))
	{
		temp_lock_holder = temp->wait_on_lock->holder;

		temp_lock_holder->priority = temp->priority;

		// 아래 코드는 절대 있으면 안 됨!! 
		// nested donation 상황에서 내가 donation하는 스레드는 딱 하나. 
		//list_insert_ordered(&temp_lock_holder->donations, &temp->donation_elem, cmp_priority, 0);
		
		temp = temp_lock_holder;
		nested_depth++;
	}
}

/*
  현재 스레드의 donations 리스트를 확인하여 해지할 lock을 보유하고 있는 스레드를 삭제한다.
*/
void remove_with_lock(struct lock *lock)
{
	struct thread *cur = thread_current(); 		// thread L 
	struct list *cur_don = &cur->donations;
	struct list_elem *e; 

	// 현재 스레드가 donation받은 리스트가 비어있지 않다면,
	if (!list_empty(cur_don)){
		// donations 리스트 순회
		for (e = list_begin(cur_don); e != list_end(cur_don); e = list_next(e)){
			// 해지할 lock을 기다리고 있는 스레드를 donations 리스트에서 모두 제거
			struct thread *e_cur = list_entry(e, struct thread, donation_elem);
			if (lock == e_cur->wait_on_lock){
				list_remove(&e_cur->donation_elem);
			}
		}
	}
}

	// 우리가 만든 코드 - 마음이 허락할 때 돌려보자
	// if (list_empty(&dn)) return;

	// // for (start=list_begin(&dn); start != list_tail(&dn); )

	// // donations 리스트를 순회
	// while(start != list_tail(&dn))
	// {
	// 	// ASSERT(start == &dn.head);
	// 	// if(start == &dn.head)
	// 	// 	start = start->next;
	// 	// 해지할 lock을 보유하고 있는 엔트리를 삭제한다.
	// 	// t는 스레드
	// 	struct thread *t = list_entry(start, struct thread, donation_elem);
	// 	if (t->wait_on_lock == lock)	// 스레드가 대기하고 있는 lock의 주소가 매개변수로 받은 lock과 같다면
	// 	{
	// 		start = list_remove(&(t->donation_elem));	// 해당 스레드(list_elem)을 donations 리스트에서 삭제함
	// 	}
	// 	else
	// 	{
	// 		start = list_next(start);
	// 	}
	// }

/*
  현재 스레드의 우선순위가 변경된 경우 실행됨, 이 때 donation을 고려하여 priority를 다시 결정함.
*/
void refresh_priority (void)
{
	// 현재 스레드의 우선순위를 기부받기 전의 우선순위로 변경
	thread_current()->priority = thread_current()->init_priority;
	
	struct list *dn = &thread_current()->donations;
	struct list_elem *traverse = list_begin(dn);

	// 현재 스레드의 donations 리스트가 비어있다면 종료
	if (list_empty(dn))
		return;

	// 현재 스레드의 donations 리스트를 우선순위 순으로 정렬
	list_sort(dn, thread_compare_donate_priority, 0);

	// donations 리스트의 맨 앞(가장 우선순위 큼)의 우선순위가 현재 스레드의 우선순위 보다 크다면,
	// 현재 스레드의 우선순위를 donations 리스트의 맨 앞(가장 우선순위 큼)의 우선순위로 변경
	struct thread *front = list_entry(list_begin(dn), struct thread, donation_elem);
	if (front->priority > thread_current()->priority)
	{
		thread_current()->priority = front->priority;
	}
}


/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

//--------------project1-priority_scheduling-end-----------------

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */	// do_fork에서 커널을 호출할 것으로 추정된다?????
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	//--------------project1-alarm-start--------------
	t->wakeup_tick = 0;
	//--------------project1-alarm-end----------------
	t->wait_on_lock = NULL;			
	t->init_priority = priority;	
	list_init(&t->donations);		
	// donation_elem 을 초기화 하지 않는 이유 : 값이 들어가기 전까지 절대 사용되지 않으므로 할 필요 없다.
	//--------------project1-alarm-end----------------
  
	//--------------project2-system_call-start----------------
	// t->fdt = (struct file*)palloc_get_multiple(PAL_ZERO, 1);
	t->next_fd = 2;
	t->fdt[0] = 0;	// stdin
	t->fdt[1] = 1;	// stdout

	/* exit 세마포어 0으로 초기화 */ 
	sema_init(&t->exit_sema, 0);

	/* fork 세마포어 0으로 초기화 */
	sema_init(&t->fork_sema, 0);

	/* free 세마포어 0으로 초기화 */
	sema_init(&t->free_sema, 0);

	list_init(&t->child_list);	// 자식들 리스트 초기화 
	// 한양대start
	// list_init(&t->file_list);
	// 한양대end
	list_push_back(&all_list, &t->all_list_elem);	// all_list에 t 추가
	//--------------project2-system_call-end------------------
}	

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
/*
	다음 스레드를 반환
*/
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))// ready_list가 빈 리스트이면 idle 스레드를 반환 -> idle 스레드만 있는 경우 (맨 처음)
		return idle_thread;
	else   //list_entry(ready_list 중 맨 앞 list elem(스레드), struct thread, list_elem 전역변수 elem)
		return list_entry(list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(	
			"movq %0, %%rsp\n"				// 커널 스택이 끝나면 OS 레지스터 내용을 팝해서 유저 스택으로 넘겨줌
			"movq 0(%%rsp),%%r15\n"			//	|
			"movq 8(%%rsp),%%r14\n"			//  |
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"		//	|
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"			//	|
			"movw (%%rsp),%%es\n"			//	|
			"addq $32, %%rsp\n"				// 커널 스택이 끝나면 OS 레지스터 내용을 팝해서 유저 스택으로 넘겨줌
			"iretq"							// 커널 스택이 끝나면 CPU 레지스터 내용을 팝해서 유저 스택으로 넘겨줌
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}


/*

*/
/*
"상태변경"
destruction_req(list 자료형)를 모두 비워주고 
현재 스레드의 상태를 매개변수 status로 바꾸고, 스케쥴 실행
*/
/* If the thread we switched from is dying, destroy its struct
	thread. This must happen later so that thread_exit() doesn't
	pull out the rug under itself.
	We just queuing the page free reqeust here because the page is
	currently used by the stack.
	The real destruction logic will be called at the beginning of the
	schedule(). 

	스레드가 running인 상태일 떄는, stack에서 Page를 사용하고 있기 때문에
	page free request를 큐에 넣고 기다린다. 
	이후, schedule()이 실행되면 먼저 destruction logic을 실행시켜 page free request를 처리한다.
*/
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);	// interrupt가 off상태이어야 함
	ASSERT (thread_current()->status == THREAD_RUNNING);// thread RUNNING상태이어야 함
	while (!list_empty (&destruction_req)) {// destruction logic 실행
		struct thread *victim =	// destruction_req의 모든 원소들(victim)을 page free 시킴
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);// 할당받은 페이지 공간을 반환함
	}
	thread_current ()->status = status;	// 현재 스레드의 상태를 인자로 받은 상태로 변경
	schedule ();						// 스케쥴 함수 실행
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
/*
	next 스레드의 status를 RUNNING으로 변경한다. 
	만약, curr이 이미 종료된 상태이고, initial_thread가 아니라면
	destruction_request list에 curr을 넣어준다.
*/
static void
schedule (void) {
	// *curr에 running 스레드 저장 
	struct thread *curr = running_thread();

	// next에 다음에 실행될 스레드 저장
	struct thread *next = next_thread_to_run();

	ASSERT (intr_get_level () == INTR_OFF);	// Interrupt가 off이어야 함
	ASSERT (curr->status != THREAD_RUNNING);// 현재 스레드가 RUNNING상태가 아니어야 함
	ASSERT (is_thread (next));				// next가 스레드이어야 함
	/* Mark us as running. */
	next->status = THREAD_RUNNING;	// next를 RUNNING상태로 변경

	/* Start new time slice. */
	thread_ticks = 0;	// next스레드의 스레드 ticks값 초기화

#ifdef USERPROG
	/* Activate the new address space. */
	//*******************************LATER**************************************************
	process_activate (next);	// 커널이 돌아가기 위한 준비 
	// 추: 프로세스 바뀌었으므로 메모리 공간 새로 할당 - 나중에 제대로 알아보기
	//*******************************LATER**************************************************
#endif
	// 스레드가 2개 이상인 경우 if문 실행 
	// curr == next라는 말은 스레드가 1개밖에 없다는 말이므로, = curr과 next가 모두 idle인 경우
	if (curr != next) {
		/*
		curr이 이미 종료된 상태이고, initial_thread가 아닐 때
		destruction_request list에 curr을 넣어준다.
		initial_thread는 destruction_request에 넣지 않음 -> main thread를  
		*/ 
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		 // running 스레드를 curr에서 next로 변경하기 전에, curr의 execution context를 저장해준다.
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}