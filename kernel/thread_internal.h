#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "thread.h"

struct thread_list_head {
    struct thread *head, *tail;
};

struct thread_list_node {
    struct thread *prev, *next;
};

// Represents a kernel or user mode thread. (User mode threads always imply a
// kernel thread.)
// The pointer to this struct is saved in the tp register while in kernel
// mode, and in the sscratch register while in usermode.
// Directly below this struct, the kernel stack begins (asm relies on this),
// which is also why the extra alignment is required.
struct thread {
    // Temporary to relieve register pressure in trap path. These registers are
    // reused by recursive trap handlers and thus valid only while interrupts
    // are disabled. Use by ASM only.
    size_t scratch_sp;
    size_t scratch_tp;

    // Registers saved by syscall trap. (It saves a subset of all registers.)
    // Saved/restored by asm.
    size_t syscall_ra;
    size_t syscall_sp;
    size_t syscall_gp;
    size_t syscall_tp;
    size_t syscall_pc;
    size_t syscall_cs[12];

    // For in-kernel thread switching (asm).
    void *kernel_sp;
    void *kernel_pc;

    // Trap filtering (primitive exception handling).
    uintptr_t trap_sp;
    uintptr_t trap_pc;
    uintptr_t trap_pagefault_lo;
    uintptr_t trap_pagefault_hi;

    // Temporary while in IRQ handling code (or after thread creation).
    struct asm_regs *user_context;

    struct vm_aspace *aspace;
    struct mmu *mmu;

    enum thread_state state;

    enum thread_priority priority;

    // Absolute kernel time at which the thread should be checked again. This
    // happens with thread_handle_timeout().
    // Used in the following states:
    //  THREAD_STATE_WAIT_FUTEX
    uint64_t wait_timeout_time;

    //Futex waiting is done by enqueuing the thread to a page struct, so the
    // full address is implicit. Store an address to reduce redundant wakeups
    // just because e.g. 2 mutexes share the same page.
    int futex_page_offset;
    struct thread *futex_next_waiter;

    // Number of handles referencing this. It legally can be 0 for a thread
    // that does not have handles to it yet.
    size_t refcount;

    struct thread_list_node all_threads;
    struct thread_list_node aspace_siblings;

    // Threads in THREAD_STATE_RUNNABLE state (list head according to priority).
    struct thread_list_node runnable;

    // Threads in any wait state. The list is sorted by wait_timeout_time.
    struct thread_list_node waiting;

    // Start of the thread allocation; implies stack size and total allocation
    // size; usually points to an unreadable guard page.
    void *base;

    // Unused. Just checking how much damn space this eats up. We try to get by
    // with 1 4K page per thread (including kernel stack), so if this gets too
    // much, move to a separate slab allocation. (Same for V extensions.)
    struct fp_regs fp_state;
} __attribute__((aligned(STACK_ALIGNMENT)));
