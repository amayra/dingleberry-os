#include "arch.h"
#include "handle.h"
#include "kernel.h"
#include "mmu.h"
#include "thread.h"
#include "virtual_memory.h"

#include <kernel/syscalls.h>

struct memcpy_params {
    void *dst, *src;
    size_t size;
};

static void do_copy_user(void *ctx)
{
    struct memcpy_params *p = ctx;
    memcpy(p->dst, p->src, p->size);
}

static bool copy_user_(void *dst, void *src, size_t size)
{
    struct memcpy_params p = {dst, src, size};
    asm volatile("csrrs zero, sstatus, %0" : : "r" (SSTATUS_SUM) : "memory");
    bool ok = run_trap_pagefaults(0, MMU_ADDRESS_LOWER_MAX, do_copy_user, &p);
    asm volatile("csrrc zero, sstatus, %0" : : "r" (SSTATUS_SUM) : "memory");
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
    struct vm_aspace *as = thread_get_aspace(thread_current());
    struct asm_regs regs = {0};
    for (size_t n = 0; n < 32; n++)
        regs.regs[n] = user_regs.regs[n];
    regs.pc = user_regs.pc;
    struct thread *t = thread_create();
    assert(t);
    thread_set_user_context(t, &regs);
    thread_set_aspace(t, as);
    printf("user created thread: %p\n", t);
}

static void *syscall_mmap(void *addr, size_t length, int flags, int handle,
                          uint64_t offset)
{
    struct vm_aspace *as = thread_get_aspace(thread_current());
    if (handle >= 0)
        return (void *)-1; // not implemented
    return vm_mmap(as, addr, length, flags, NULL, offset);
}

static int syscall_fork(void)
{
    struct thread *t = thread_current();
    struct vm_aspace *as = thread_get_aspace(t);
    struct vm_aspace *as2 = vm_aspace_create();
    if (!as2)
        return -1;
    struct asm_regs regs;
    thread_fill_syscall_saved_regs(t, &regs);
    regs.regs[10] = 0; // child
    struct thread *t2 = thread_create();
    if (!t2)
        panic("too cheap for error handling\n");
    thread_set_user_context(t2, &regs);
    thread_set_aspace(t2, as2);
    if (!vm_fork(as2, as))
        panic("nope\n");
    mmu_switch_to(thread_get_mmu(t2));
    if (!handle_table_create(vm_aspace_get_mmu(as2)))
        panic("Failed to create user handle table.\n");
    mmu_switch_to(thread_get_mmu(thread_current()));
    printf("fork thread %p as %p\n", t2, as2);
    struct handle h = {
        .type = HANDLE_TYPE_THREAD,
        .u = {
            .thread = t2,
        },
    };
    // parent returns thread handle
    return handle_add_or_free(&h);
}

static int syscall_close(int64_t handle)
{
    struct handle *h = handle_lookup(handle);
    if (!h)
        return -1;
    handle_free(h);
    return 0;
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
    [SYS_MMAP]                  = {1, syscall_mmap},
    [SYS_FORK]                  = {1, syscall_fork},
    [SYS_CLOSE]                 = {1, syscall_close},
    // Update SYSCALL_COUNT if you add or remove an entry.
    // Also make sure all entrypoint fields are non-NULL.
};

static_assert(ARRAY_ELEMS(syscall_table) == SYSCALL_COUNT, "");
