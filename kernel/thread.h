#pragma once

#include <stddef.h>

#include "memory.h"

struct vm_aspace;
struct phys_page;

// The layout of this struct is fully fixed in asm.
struct asm_regs {
    // x0-x31 (x0 is ignored; included to avoid confusing register numbers)
    size_t regs[32];
    // Assorted CSRs (only some of them are written when restoring context)
    size_t pc;
    size_t status;
    size_t cause;
    size_t tval;
    size_t ip;
} __attribute__((aligned(STACK_ALIGNMENT)));

struct fp_regs {
    long double regs[32];
    uint32_t fcsr;
};

// Static priorities.
enum thread_priority {
    THREAD_PRIORITY_IDLE,
    THREAD_PRIORITY_NORMAL,
    THREAD_PRIORITY_NUM         // not a valid priority
};

enum thread_state {
    THREAD_STATE_NO_CONTEXT,    // early init state; can't be scheduled
    THREAD_STATE_FINE,          // this thread is totally fine and takes it easy
    THREAD_STATE_RUNNABLE,      // currently waiting to be scheduled
    THREAD_STATE_WAIT_FUTEX,    // waiting on a futex
    THREAD_STATE_DEAD,          // fucked up
};

// Create a kernel/user thread. You need to call thread_set_*_context() to
// properly initialize its state.
struct thread *thread_create(void);

// Setup the thread's context for a kernel thread. fn(ctx) will be called next
// time the thread is scheduled (and it must not return).
// Note: calling this after the thread has been scheduled at least once is
//       undefined behavior; you can't change a running thread's context.
void thread_set_kernel_context(struct thread *t, void (*fn)(void *ctx), void *ctx);

// Setup the thread's context for a kernel/user thread. The next time the thread
// is scheduled, it will return to userspace with the given set of registers,
// If the context can't be set (such as being a kernel thread, or stuck in a
// syscall), this returns false.
bool thread_set_user_context(struct thread *t, struct asm_regs *regs);

// Free the thread. It is an error to free a thread that is still referenced by
// handles.
void thread_free(struct thread *t);

// Return current kernel thread.
struct thread *thread_current(void);

void thread_fill_syscall_saved_regs(struct thread *t, struct asm_regs *regs);

// Set the thread's aspace. Normally this is called only once (and only for
// userspace threads).
void thread_set_aspace(struct thread *t, struct vm_aspace *aspace);

// Return the thread's aspace.
struct vm_aspace *thread_get_aspace(struct thread *t);

// Convenience for vm_aspace_get_mmu(thread_get_aspace(t)).
struct mmu *thread_get_mmu(struct thread *t);

// Cooperative context switch.
void thread_switch_to(struct thread *t);

// Return the current state.
enum thread_state thread_get_state(struct thread *t);

// Set new thread state. The caller must ensure the state transition makes
// sense.
void thread_set_state(struct thread *t, enum thread_state state);

// Change priority. It might be needed to call thread_reschedule() to make
// the new priority take effect.
void thread_set_priority(struct thread *t, enum thread_priority priority);

// Schedule next thread to run. If the current thread is runnable, this is
// effectively a yield.
void thread_reschedule(void);

// Wakeup max_wakeups threads queued as futex waiters for this page. offset is
// the offset within the page, or -1 to affect the entire page.
uint64_t futex_wake(struct phys_page *page, int offset, uint64_t max_wakeups);

// Make the current thread wait for a corresponding futex_wake() event. This
// only handles sleeping.
void futex_wait(struct phys_page *page, int offset, uint64_t timeout_time);

// Disable interrupt trap. Returns whether it was enabled before.
bool ints_disable(void);

// Undo ints_disable, i.e. re-enable interrupts if they were enabled before.
void ints_restore(bool ints_disable_return_value);

// Enable interrupt trap.
void ints_enable(void);

void threads_init(void (*boot_handler)(void));

// Run fn(fn_ctx) once and return true. If a page fault happens, and the fault
// address is within the [ok_lo, ok_hi] region (ok_hi is inclusive!), then
// execution of fn (and any functions called by fn) is stopped, and false is
// returned. If a fault outside of the ok_ region happens, the kernel crash
// handler is invoked.
// Nested use of this is disallowed, and an internal error.
bool run_trap_pagefaults(uintptr_t ok_lo, uintptr_t ok_hi, void (*fn)(void *),
                         void *fn_ctx);
