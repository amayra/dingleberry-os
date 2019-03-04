#pragma once

#include <stddef.h>

#include "memory.h"

struct vm_aspace;

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

// Create a kernel/user thread. For a kernel thread, pass NULL for aspace.
// In both cases, init_regs needs to be passed. This is copied and on the first
// context switch used to initialize the exact execution point (which can be
// kernel or userspace).
// If this is a kernel thread, the sp register is overwritten,
// and set to the start of the kernel stack, tp/gp/status are overwritten to
// their their proper values.
struct thread *thread_create(struct vm_aspace *aspace, struct asm_regs *init_regs);

// Helper function for creating a kernel thread. You can't return from the
// thread. The thread function is called once the thread is first switched to.
struct thread *thread_create_kernel(void (*thread)(void *ctx), void *ctx);

// Return current kernel thread.
struct thread *thread_current(void);

void thread_fill_syscall_saved_regs(struct thread *t, struct asm_regs *regs);

// Return the thread's aspace.
struct vm_aspace *thread_get_aspace(struct thread *t);

// Cooperative context switch.
void thread_switch_to(struct thread *t);

// Schedule next thread to run.
void thread_reschedule(void);

// Disable interrupt trap. Returns whether it was enabled before.
bool ints_disable(void);

// Undo ints_disable, i.e. re-enable interrupts if they were enabled before.
void ints_restore(bool ints_disable_return_value);

// Enable interrupt trap.
void ints_enable(void);

void threads_init(void (*boot_handler)(void));

extern bool (*g_filter_kernel_pagefault)(struct asm_regs *regs,
                                         void *memory_addr);
