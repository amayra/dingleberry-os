#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "thread.h"

// Represents a kernel or user mode thread. (User mode threads always imply a
// kernel thread.)
// The pointer to this struct is saved in the tp register while in kernel
// mode, and in the sscratch register while in usermode.
// Directly below this struct, the kernel stack begins (asm relies on this),
// which is also why the extra alignment is required.
struct thread {
    // Note: start of fields that are accessed from asm. Don't change them
    //       without adjusting the offsets in the asm.

    // Temporary to relieve register pressure in trap path. These registers are
    // reused by recursive trap handlers and thus valid only while interrupts
    // are disabled.
    size_t scratch_sp;
    size_t scratch_tp;

    // Registers saved by syscall trap. (It saves a subset of all registers.)
    size_t syscall_ra;
    size_t syscall_sp;
    size_t syscall_gp;
    size_t syscall_tp;
    size_t syscall_pc;

    size_t syscall_cs[12];

    // End of asm fields.

    // For in-kernel thread switching.
    void *kernel_sp;
    void *kernel_pc;

    struct vm_aspace *aspace;
    struct mmu *mmu;

    struct {
        struct thread *prev, *next;
    } all_threads;

    struct {
        struct thread *prev, *next;
    } mmu_siblings;

    // Start of the thread allocation; implies stack size and total allocation
    // size; usually points to an unreadable guard page.
    void *base;

    // Unused. Just checking how much damn space this eats up. We try to get by
    // with 1 4K page per thread (including kernel stack), so if this gets too
    // much, move to a separate slab allocation. (Same for V extensions.)
    struct fp_regs fp_state;
} __attribute__((aligned(STACK_ALIGNMENT)));
