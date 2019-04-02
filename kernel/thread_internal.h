#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kernel/api.h>

#include "thread.h"

struct thread_list_head {
    struct thread *head, *tail;
};

struct thread_list_node {
    struct thread *prev, *next;
};

struct futex_waiter {
    struct futex_waiter *next;
    struct thread *t;
    struct phys_page *page;
    int offset;
    int result;
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
    size_t syscall_sp;
    size_t syscall_gp;
    size_t syscall_tp;
    size_t syscall_pc;
    size_t syscall_sstatus;
    size_t syscall_cs[12];

    // For in-kernel thread switching (asm).
    void *kernel_sp;
    void *kernel_pc;

    // In THREAD_STATE_WAIT_IPC, this specifies the handle that is being used.
    // The handle must always be consistent (e.g. when the handle is closed by
    // an unrelated syscall, there is enough information to update all threads
    // waiting on it).
    kern_handle ipc_handle;
    // THREAD_STATE_WAIT_IPC / THREAD_STATE_WAIT_IPC_SEND siblings
    struct thread *ipc_list;
    // Saved reply handle. Only valid for ipc_handle==HANDLE_TYPE_IPC_LISTENER.
    // Avoids going though alloc/dealloc.
    kern_handle ipc_free_reply_handle;
    // Used to return IPC arguments for syscall return. (Technically, the field
    // is redundant, as the struct is always allocated on the same stack
    // position of the thread. The field is used for clarity.)
    struct ipc_info *ipc_info;

    // See mmu_get_satp(); used by asm.
    uint64_t mmu_satp;

    struct handle_table handle_table;

    // Trap filtering (primitive exception handling).
    uintptr_t trap_sp;
    uintptr_t trap_pc;
    uintptr_t trap_pagefault_lo;
    uintptr_t trap_pagefault_hi;
    bool trap_handler_running;

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

    // For THREAD_STATE_WAIT_FUTEX.
    struct futex_waiter *futex;

    // Number of handles referencing this. It legally can be 0 for a thread
    // that does not have handles to it yet.
    size_t refcount;

    struct thread_list_node all_threads;
    struct thread_list_node aspace_siblings;

    // State-specific siblings. E.g.:
    //  THREAD_STATE_RUNNABLE: runnable threads sorted by priority
    //  THREAD_STATE_WAIT_FUTEX:
    //      waiting threads sorted by timeout
    struct thread_list_node st_siblings;

    // Start of the thread allocation; implies stack size and total allocation
    // size; usually points to an unreadable guard page.
    void *base;

    // Unused. Just checking how much damn space this eats up. We try to get by
    // with 1 4K page per thread (including kernel stack), so if this gets too
    // much, move to a separate slab allocation. (Same for V extensions.)
    struct fp_regs fp_state;

    // For KERN_FN_TLS
    size_t user_tls[KERN_TLS_NUM];
} __attribute__((aligned(STACK_ALIGNMENT)));

enum {
    ASM_EXCEPTION_TYPE_KERNEL_LOAD  = 1 << 0,
    ASM_EXCEPTION_TYPE_USER_LOAD    = 2 << 0,
    ASM_EXCEPTION_TYPE_USER_STORE   = 2 << 0,
};

// Layout and size hardcoded in ASM.
struct asm_exception_entry {
    void *code_start;
    void *code_end;
    void *code_target;
    size_t type;
};

extern const struct asm_exception_entry asm_exception_table[];
