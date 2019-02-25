#include "arch.h"
#include "kernel.h"
#include "thread.h"

#include <kernel/syscalls.h>

// per CPU
static void *trap_sp;

bool memcpy_with_trap(void **sp, void *dst, void *src, size_t size);
void memcpy_with_trap_restore_pc();

static bool filter_copy_user(struct asm_regs *regs, void *memory_addr)
{
    // Only filter the page fault if the user address
    if ((uintptr_t)memory_addr <= MMU_ADDRESS_LOWER_MAX && trap_sp) {
        // Force direct return. This assumes that no code in the copy path
        // (basically memcpy()) modifies global registers like gp.
        regs->regs[2] = (uintptr_t)trap_sp;
        regs->pc = (uintptr_t)memcpy_with_trap_restore_pc;
        trap_sp = NULL;
        return true;
    }
    return false;
}

static bool copy_user_(void *dst, void *src, size_t size)
{
    assert(!g_filter_kernel_pagefault);
    g_filter_kernel_pagefault = filter_copy_user;
    asm volatile("csrrs zero, sstatus, %0" : : "r" (SSTATUS_SUM) : "memory");
    bool ok = memcpy_with_trap(&trap_sp, dst, src, size);
    asm volatile("csrrc zero, sstatus, %0" : : "r" (SSTATUS_SUM) : "memory");
    g_filter_kernel_pagefault = NULL;
    return ok;
}

static bool valid_user_address(void *user_addr, size_t size)
{
    return size <= MMU_ADDRESS_LOWER_MAX &&
        (uintptr_t)user_addr <= MMU_ADDRESS_LOWER_MAX + 1 - size;
}

// Copy from/to userspaces addresses. The user_src address is sanitized, and
// faults to it are caught. On a fault, false is returned, and *dst might have
// been partially written to.
static bool copy_from_user(void *dst, void *user_src, size_t size)
{
    if (!valid_user_address(user_src, size))
        return false;
    assert((uintptr_t)dst >= KERNEL_SPACE_BASE); // just a kernel code bug

    return copy_user_(dst, user_src, size);
}

static bool copy_to_user(void *user_dst, void *src, size_t size)
{
    if (!valid_user_address(user_dst, size))
        return false;
    assert((uintptr_t)src >= KERNEL_SPACE_BASE); // just a kernel code bug

    return copy_user_(user_dst, src, size);
}

// Pseudo entry for out of bounds syscall values. (Called from trap.S.)
size_t syscall_unavailable(size_t nr)
{
    printf("Unknown syscall %"PRIu64".\n", nr);
    return -1;
}

static size_t syscall_get_timer_freq(void)
{
    return timer_frequency;
}

static void syscall_debug_write_char(size_t v)
{
    printf("%c", (char)v);
}

static void syscall_debug_stop(void)
{
    panic("User stop.\n");
}

static void syscall_thread_create(void *regs_arg)
{
    struct sys_thread_regs user_regs;
    if (!copy_from_user(&user_regs, regs_arg, sizeof(user_regs)))
        return;
    struct aspace *aspace = thread_get_aspace(thread_current());
    struct asm_regs regs = {0};
    for (size_t n = 0; n < 32; n++)
        regs.regs[n] = user_regs.regs[n];
    regs.pc = user_regs.pc;
    struct thread *t = thread_create(aspace, &regs);
    assert(t);
    printf("user created thread: %p\n", t);
}

// All of the following offsets/sizes are hardcoded in ASM.

struct syscall_entry {
    size_t num_return_values;
    const void *entrypoint;
};

const struct syscall_entry syscall_table[] = {
    [SYS_GET_TIMER_FREQ]        = {1, syscall_get_timer_freq},
    [SYS_DEBUG_WRITE_CHAR]      = {0, syscall_debug_write_char},
    [SYS_DEBUG_STOP]            = {0, syscall_debug_stop},
    [SYS_THREAD_CREATE]         = {0, syscall_thread_create},
    // update ASM_SYSCALL_COUNT if you add or remove an entry
};
