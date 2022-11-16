/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
/*
semaphore 초기화(semaphore의 value, waiters list 초기화)
*/
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value; // semaphore value(공유 자원의 개수)
	list_init (&sema->waiters); // semaphore waiters list(스레드들)
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
/*
cond_signal() 올 때까지 기다림. while문을 반복하면서
현재 스레드들을 semaphore의 waiters 리스트에 우선순위 순으로 삽입
*/
void
sema_down (struct semaphore *sema) {

	// waiters 리스트 삽입 시, 우선순위대로 삽입되도록 수정

	enum intr_level old_level;

	ASSERT (sema != NULL);	// semaphore가 있는지 확인.
	ASSERT (!intr_context ());	// interrupt 실행할 게 없는 지 확인.

	old_level = intr_disable ();	// interrupt를 disable 시킴.
	// timer_interrupt, I/O interrupt 

	// 사용할 수 있는 공유 자원(semaphore value)이 없을 때(while문으로)
	// waiters list에 현재 스레드들을 우선순위 순으로 삽입
	while (sema->value == 0) {
		//--------------project1_2-priority_scheduling-start---------------
		// list_push_back (&sema->waiters, &thread_current ()->elem); // 기존 코드
		
		list_insert_ordered (&sema->waiters, &thread_current ()->elem, cmp_priority, 0);

		//--------------project1_2-priority_scheduling-end-----------------

		// 현재 스레드를 BLOCK상태로 변경 후 schedule(next를 RUNNING상태로)
		thread_block ();
	}

	// semaphore value 1 뺌
	sema->value--;

	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
/*
waiters_list가 비어있지 않은 경우,
waiters_list가 맨 처음 스레드를 unblock하여
ready_list에 넣고 READY 상태로 변경.
*/
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters))
	//--------------project1_2-priority_scheduling-start---------------
	{
		// 스레드가 waiters list에 있는 동안 우선순위가 변경되었을 경우를 고려하여
		// 세마포어에 있는 스레드들을 우선순위 정렬
		list_sort(&sema->waiters, cmp_priority, 0);

		// ready list에 있는 애들 중 우선순위가 가장 높은 스레드를
		// RUNNING 상태로 변경하기 때문에

		// waiters list에서 맨 처음 스레드를
		// unblock(READY로 변경, ready_list 삽입)한다.
		thread_unblock (list_entry (list_pop_front (&sema->waiters),
					struct thread, elem));
	}

	// 공간을 확보한다. 
	sema->value++;

	// priority preemption
	test_max_priority();

	//--------------project1_2-priority_scheduling-end-----------------
	intr_set_level (old_level);
}


//--------------project1_2-priority_scheduling-start---------------

/*
세마포어의 waiters_list의 맨앞 스레드의 우선순위를 비교.
높으면 1(true), 낮으면 0(false) 반환.
*/
bool cmp_sem_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	// sa는 (list_elem 타입의)a를 가진 semaphore_elem.
	struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);

	// l_a는 (semaphore_elem) sa의 세마포어의 waiters_list의 맨 앞에 있는 list_elem.
	struct list_elem *l_a = list_begin(&(sa->semaphore.waiters));
	struct list_elem *l_b = list_begin(&(sb->semaphore.waiters));

	// t_a는 (list_elem)l_a를 가진 스레드.
	struct thread *t_a = list_entry(l_a, struct thread, elem);
	struct thread *t_b = list_entry(l_b, struct thread, elem);
	
	return t_a->priority > t_b->priority;
}

//--------------project1_2-priority_scheduling-end-----------------

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	// 기존 코드
	// sema_down (&lock->semaphore);
	// lock->holder = thread_current ();

	// 해당 lock의 holder가 존재한다면, 아래 작업을 수행한다. 
	if (lock->holder != NULL)
	{
		// 현재 스레드의 wait_on_lock 변수에 획득하기를 기다리는 lock의 주소를 저장
		thread_current()->wait_on_lock = lock;

		// multiple donation을 고려하기 위해, 이전상태의 우선순위를 기억
		// priority를 다시 init_priority로 바꿈
		thread_current()->priority = thread_current()->init_priority;
		// donation을 받은 스레드의 thread 구조체를 list로 관리한다. 
		//?????????????????
		// list_init(&thread_current()->donations);

		// priority donation을 수행하기 위해 donate_priority() 함수 호출
		donate_priority();
	}
	
	sema_down (&lock->semaphore);

	// lock을 획득한 후, lock holder를 갱신한다.
	lock->holder = thread_current();
	
	thread_current()->wait_on_lock = NULL;// ??????????????????????????????
	
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	lock->holder = NULL;

	// remove_with_lock() 함수 추가
	remove_with_lock(lock);
	// // refresh_priority() 함수 추가
	refresh_priority();

	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
/*
새로운 세마포어 초기화.
condtional variable의 waiters 리스트에 세마포어 우선순위 순으로 추가.
lock(mutex_lock)을 반환 후, sema_down 실행하고 lock(mutex_lock) 획득
*/
void
cond_wait (struct condition *cond, struct lock *lock) {

	// 세마포어이지만, conditional variable 관리를 위해 semaphore_elem이라는 더 큰 구조체를 만듦
	struct semaphore_elem waiter; // elem(list_elem)과 semaphore(semaphore)를 멤버로 가짐

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	// 세마포어의 value를 0으로, waiters 리스트를 초기화
	sema_init (&waiter.semaphore, 0);

	//--------------project1_2-priority_scheduling-start---------------
	// list_push_back (&cond->waiters, &waiter.elem); // 기존 코드

	// conditional variable의 waiters 리스트에 waiter.elem(semaphore_elem->elem)을 우선순위 순으로 넣어줌.
	list_insert_ordered(&cond->waiters, &waiter.elem, cmp_sem_priority, 0);
	//--------------project1_2-priority_scheduling-end-----------------

	/* 
	lock을 반환함(lock의 holder를 NULL로), 여기서 lock은 mutex_lock.
	cond_wait() 호출 이전에 lock_acquire()을 했기 때문에 여기서 lock_release를 함.
	여기로 오는 동안 스레드의 상태가 바뀌면 안되기 때문에, lock을 잠궈서 오다가,
	sema_down에서 스레드의 상태가 바뀔수 있기 때문에 lock_release 해줘야함.
	*/
	lock_release (lock);

	// 공유 자원에 자리가 없으면 세마포어의 waiters 리스트에 우선순위 순으로 삽입하고 BLOCK상태로 기다림. 
	sema_down (&waiter.semaphore);

	// lock을 획득함.(현재 스레드가 lock의 holder로)
	// 원래 구문으로 돌아가는 동안 스레드의 상태가 바뀌면 안되서 lock을 획득.
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
/* 
임계 구역(critical section) 맨 앞에서 기다리는 프로세스에게 '이제 가도 좋다'고 신호를 줌
*/
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
	{
		// 스레드의 우선순위가 중간에 변경되었을 수도 있기 때문에
		// condition variable의 waiters list를 우선순위로 재정렬
		// 조건 변수 안에 있는 세마포어들을 우선순위 정렬
		list_sort(&cond->waiters, cmp_sem_priority, 0);

		// conditional variable waiters list들 중 우선 순위가 가장 높은 스레드를
		// sema_up() 시킨다.
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);	
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
/*
모든 세마포어에 cond_signal() 호출
*/
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}


