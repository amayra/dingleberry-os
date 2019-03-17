#include "arch.h"
#include "handle.h"
#include "kernel.h"
#include "mmu.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "thread.h"
#include "time.h"
#include "virtual_memory.h"

#include <kernel/api.h>

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

static bool valid_user_address(uintptr_t user_addr, size_t size)
{
    return size <= MMU_ADDRESS_LOWER_MAX &&
        user_addr <= MMU_ADDRESS_LOWER_MAX + 1 - size;
}

// Copy from/to userspaces addresses. The user_src address is sanitized, and
// faults to it are caught. On a fault, false is returned, and *dst might have
// been partially written to.
static bool copy_from_user(void *dst, uintptr_t user_src, size_t size)
{
    if (!valid_user_address(user_src, size))
        return false;
    assert((uintptr_t)dst >= KERNEL_SPACE_BASE); // just a kernel code bug

    return copy_user_(dst, (void *)user_src, size);
}

static bool copy_to_user(uintptr_t user_dst, void *src, size_t size)
{
    if (!valid_user_address(user_dst, size))
        return false;
    assert((uintptr_t)src >= KERNEL_SPACE_BASE); // just a kernel code bug

    return copy_user_((void *)user_dst, src, size);
}

// Pseudo entry for out of bounds syscall values. (Called from trap.S.)
size_t syscall_unavailable(size_t nr)
{
    printf("Unknown syscall %"PRIu64".\n", nr);
    return -1;
}

static int syscall_get_time(uintptr_t time_ptr)
{
    struct kern_timespec t;
    time_to_timespec(&t, time_get());
    if (!copy_to_user(time_ptr, &t, sizeof(t)))
        return -1;
    return 0;
}

static void syscall_debug_write_char(size_t v)
{
    printf("%c", (char)v);
}

static void syscall_debug_stop(void)
{
    panic("User stop.\n");
}

static struct thread *lookup_thread(int64_t handle)
{
    if (handle == KERN_HANDLE_INVALID)
        return thread_current();
    struct handle *h = handle_lookup_type(handle, HANDLE_TYPE_THREAD);
    return h ? h->u.thread : NULL;
}

static int64_t syscall_thread_create(int64_t aspace_handle, int new_aspace)
{
    struct thread *t = lookup_thread(aspace_handle);
    if (!t)
        return -1; // bad handle

    struct thread *new = thread_create();
    if (!new)
        return -1; // OOM

    struct vm_aspace *as = thread_get_aspace(t);
    if (new_aspace) {
        as = vm_aspace_create();
        if (!as) {
            thread_free(new);
            return -1; // OOM
        }
        struct mmu *mmu = vm_aspace_get_mmu(as);
        mmu_switch_to(mmu);
        bool ok = handle_table_create(mmu);
        mmu_switch_to(thread_get_mmu(thread_current()));
        if (!ok) {
            vm_aspace_free(as);
            thread_free(new);
            return -1; // OOM
        }
    }

    thread_set_aspace(new, as);

    struct handle h = {
        .type = HANDLE_TYPE_THREAD,
        .u = {
            .thread = new,
        },
    };
    return handle_add_or_free(&h);
}

static int syscall_thread_set_context(int thread_handle, uintptr_t regs_arg)
{
    struct thread *t = lookup_thread(thread_handle);
    if (!t)
        return -1; // bad handle

    struct kern_thread_regs user_regs;
    if (!copy_from_user(&user_regs, regs_arg, sizeof(user_regs)))
        return -1; // bad pointer
    struct asm_regs regs = {0};
    for (size_t n = 0; n < 32; n++)
        regs.regs[n] = user_regs.regs[n];
    regs.pc = user_regs.pc;

    if (!thread_set_user_context(t, &regs))
        return -1; // thread context cannot be changed

    return 0;
}

static void *syscall_mmap(uint64_t dst_handle, void *addr, size_t length,
                          int flags, int handle, uint64_t offset)
{
    struct thread *t = lookup_thread(dst_handle);
    if (!t)
        return (void *)-1; // bad handle
    struct vm_aspace *as = thread_get_aspace(t);
    if (handle >= 0)
        return (void *)-1; // not implemented
    return vm_mmap(as, addr, length, flags, NULL, offset);
}

static int syscall_mprotect(uint64_t dst_handle, void *addr, size_t length,
                            unsigned remove_flags, unsigned add_flags)
{
    struct thread *t = lookup_thread(dst_handle);
    if (!t)
        return -1; // bad handle
    struct vm_aspace *as = thread_get_aspace(t);
    return vm_mprotect(as, addr, length, remove_flags, add_flags) ? 0 : -1;
}

static int64_t syscall_copy_aspace(int64_t src, int64_t dst, int emulate_fork)
{
    struct thread *t_src = lookup_thread(src);
    struct thread *t_dst = lookup_thread(dst);
    if (!t_src || !t_dst)
        return -1; // bad handle

    if (!vm_fork(thread_get_aspace(t_dst), thread_get_aspace(t_src)))
        return -1; // OOM or dst not empty

    if (emulate_fork) {
        struct asm_regs regs;
        thread_fill_syscall_saved_regs(t_src, &regs);
        regs.regs[10] = 1; // a0=1 => child
        if (!thread_set_user_context(t_dst, &regs))
            return -1; // thread context cannot be changed
    }

    return 0;
}

static int syscall_close(int64_t handle)
{
    struct handle *h = handle_lookup(handle);
    if (!h)
        return -1;
    handle_free(h);
    return 0;
}

static bool get_futex_addr(uintptr_t uaddr, struct phys_page **page, int *offset)
{
    struct mmu *mmu = thread_get_mmu(thread_current());
    *page = NULL;
    *offset = uaddr & (PAGE_SIZE - 1);

    uaddr -= *offset;

    uint64_t phys_addr;
    size_t page_size;
    int flags;
    if (!mmu_read_entry(mmu, (void *)uaddr, &phys_addr, &page_size, &flags))
        return false;

    *page = phys_page_get(phys_addr);
    if (!*page)
        return false;

    if ((*page)->usage != PAGE_USAGE_USER)
        return false;

    return true;
}

static int syscall_futex(int op, uintptr_t timeptr, uintptr_t uaddr, size_t val)
{
    switch (op) {
    case KERN_FUTEX_WAIT: {
        uint64_t timeout = UINT64_MAX;
        if (timeptr) {
            struct kern_timespec time;
            if (!copy_from_user(&time, timeptr, sizeof(time)))
                return -1; // invalid timeptr pointer
            // (Linux uses a relative time here, we don't.)
            timeout = time_from_timespec(&time);
        }
        // (this would require an actual atomic OP if we had SMP support)
        int cur;
        if (!copy_from_user(&cur, uaddr, sizeof(cur)))
            return -1; // invalid user address
        if (cur != val)
            return -1; // value changed; try again
        struct phys_page *page;
        int offset;
        if (!get_futex_addr(uaddr, &page, &offset))
            return -1; // ???
        return futex_wait(page, offset, timeout);
    }
    case KERN_FUTEX_WAKE: {
        // Ensure presence.
        if (!copy_from_user(&(int){0}, uaddr, sizeof(int)))
            return -1; // invalid user address
        struct phys_page *page;
        int offset;
        if (!get_futex_addr(uaddr, &page, &offset))
            return -1; // ???
        return futex_wake(page, offset, val);
    }
    default:
        return -1;
    }
}

static int syscall_yield(void)
{
    thread_reschedule();
    return 0;
}

// All of the following offsets/sizes are hardcoded in ASM.

struct syscall_entry {
    size_t num_return_values;
    const void *entrypoint;
};

const struct syscall_entry syscall_table[] = {
    [KERN_FN_GET_TIME]              = {1, syscall_get_time},
    [KERN_FN_DEBUG_WRITE_CHAR]      = {0, syscall_debug_write_char},
    [KERN_FN_DEBUG_STOP]            = {0, syscall_debug_stop},
    [KERN_FN_THREAD_CREATE]         = {1, syscall_thread_create},
    [KERN_FN_THREAD_SET_CONTEXT]    = {1, syscall_thread_set_context},
    [KERN_FN_MMAP]                  = {1, syscall_mmap},
    [KERN_FN_MPROTECT]              = {1, syscall_mprotect},
    [KERN_FN_COPY_ASPACE]           = {1, syscall_copy_aspace},
    [KERN_FN_CLOSE]                 = {1, syscall_close},
    [KERN_FN_FUTEX]                 = {1, syscall_futex},
    [KERN_FN_YIELD]                 = {1, syscall_yield},
    // Update SYSCALL_COUNT if you add or remove an entry.
    // Also make sure all entrypoint fields are non-NULL.
};

static_assert(ARRAY_ELEMS(syscall_table) == SYSCALL_COUNT, "");

void syscalls_self_check(void)
{
    for (size_t n = 0; n < ARRAY_ELEMS(syscall_table); n++) {
        if (!syscall_table[n].entrypoint)
            panic("Missing syscall entry %zu.\n", n);
    }
}
