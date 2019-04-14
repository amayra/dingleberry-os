#include "arch.h"
#include "handle.h"
#include "ipc.h"
#include "kernel.h"
#include "mmu.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "slob.h"
#include "thread.h"
#include "thread_internal.h"
#include "time.h"
#include "virtual_memory.h"

#include <kernel/api.h>

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
    struct asm_regs regs;
    thread_fill_syscall_saved_regs(thread_current(), &regs);
    panic("User stop from PC=%p.\n", (void *)regs.pc);
}

static struct thread *lookup_thread(kern_handle handle)
{
    struct thread *t = thread_current();
    if (handle == KERN_HANDLE_INVALID)
        return t;
    struct handle *h = handle_lookup_type(t, handle, HANDLE_TYPE_THREAD);
    return h ? h->u.thread : NULL;
}

static kern_handle syscall_thread_create(kern_handle aspace, int new_aspace)
{
    struct thread *t = lookup_thread(aspace);
    if (!t)
        return -1; // bad handle

    struct thread *new = thread_create();
    if (!new)
        return -1; // OOM

    struct vm_aspace *as = thread_get_aspace(t);
    if (new_aspace) {
        as = vm_aspace_create();
        if (!as) {
            thread_set_state(new, THREAD_STATE_DEAD);
            return -1; // OOM
        }
        thread_set_aspace(new, as);
        if (!handle_table_create(new)) {
            thread_set_state(new, THREAD_STATE_DEAD);
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
    return handle_add_or_free(thread_current(), &h);
}

static int syscall_thread_set_context(kern_handle thread,  uintptr_t regs_arg)
{
    struct thread *t = lookup_thread(thread);
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

static void *syscall_mmap(kern_handle dst, void *addr, size_t length,
                          int flags, int handle, uint64_t offset)
{
    struct thread *t = lookup_thread(dst);
    if (!t)
        return (void *)-1; // bad handle
    struct vm_aspace *as = thread_get_aspace(t);
    if (KERN_IS_HANDLE_VALID(handle))
        return (void *)-1; // not implemented
    return vm_mmap(as, addr, length, flags, NULL, offset);
}

static int syscall_munmap(kern_handle dst, void *addr, size_t length)
{
    struct thread *t = lookup_thread(dst);
    if (!t)
        return -1; // bad handle
    struct vm_aspace *as = thread_get_aspace(t);
    return vm_munmap(as, addr, length) ? 0 : -1;
}

static int syscall_mprotect(int64_t dst_handle, void *addr, size_t length,
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

static int syscall_close(kern_handle handle)
{
    struct thread *t = thread_current();
    struct handle *h = handle_lookup(t, handle);
    if (!h)
        return -1;
    handle_free(t, h);
    return 0;
}

static kern_handle syscall_copy_handle(kern_handle dst, kern_handle handle)
{
    struct thread *t = lookup_thread(dst);
    struct handle *h = handle_lookup(thread_current(), handle);
    if (!t || !h)
        return -1; // bad handle

    struct handle *new = handle_alloc(t);
    if (!handle_vtable[h->type]->ref(new, h)) {
        handle_free(t, new);
        new = NULL;
    }

    return handle_get_id(t, new);
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

static size_t syscall_tls(kern_handle handle, int op, unsigned index, size_t val)
{
    struct thread *t = lookup_thread(handle);
    if (!t)
        return (size_t)-1; // bad handle
    switch (op) {
    case KERN_TLS_GET:
        if (index >= KERN_TLS_NUM)
            return val; // invalid index
        return t->user_tls[index];
    case KERN_TLS_SET:
        if (index >= KERN_TLS_NUM)
            return (size_t)-1; // invalid index
        t->user_tls[index] = val;
        return 0;
    }
    return (size_t)-1; // unknown OP
}

static kern_handle syscall_memobj_create(void)
{
    return -1;
}

static kern_handle syscall_ipc_listener_create(void)
{
    struct ipc_listener *l = slob_allocz(&ipc_listener_slob);
    if (!l)
        return -1; // OOM
    l->refcount_listeners += 1;
    struct handle h = {
        .type = HANDLE_TYPE_IPC_LISTENER,
        .u = {
            .ipc_listener = {
                .listener = l,
            },
        },
    };
    return handle_add_or_free(thread_current(), &h);
}

static kern_handle syscall_ipc_target_create(kern_handle listener, size_t ud)
{
    struct handle *hl =
        handle_lookup_type(thread_current(), listener, HANDLE_TYPE_IPC_LISTENER);
    if (!hl)
        return -1; // invalid listener handle
    struct ipc_listener *l = hl->u.ipc_listener.listener;
    l->refcount_targets += 1;
    struct handle h = {
        .type = HANDLE_TYPE_IPC_TARGET,
        .u = {
            .ipc_target = {
                .listener = l,
                .user_data = ud,
            },
        },
    };
    return handle_add_or_free(thread_current(), &h);
}

// This array is used in ASM.
const void *const syscall_table[] = {
    // The IPC syscall is dispatched separately in asm.
    [KERN_FN_IPC]                   = syscall_unavailable,
    [KERN_FN_IPC_LISTENER_CREATE]   = syscall_ipc_listener_create,
    [KERN_FN_IPC_TARGET_CREATE]     = syscall_ipc_target_create,
    [KERN_FN_MEMOBJ_CREATE]         = syscall_memobj_create,
    [KERN_FN_GET_TIME]              = syscall_get_time,
    [KERN_FN_DEBUG_WRITE_CHAR]      = syscall_debug_write_char,
    [KERN_FN_DEBUG_STOP]            = syscall_debug_stop,
    [KERN_FN_THREAD_CREATE]         = syscall_thread_create,
    [KERN_FN_THREAD_SET_CONTEXT]    = syscall_thread_set_context,
    [KERN_FN_MMAP]                  = syscall_mmap,
    [KERN_FN_MPROTECT]              = syscall_mprotect,
    [KERN_FN_COPY_ASPACE]           = syscall_copy_aspace,
    [KERN_FN_CLOSE]                 = syscall_close,
    [KERN_FN_FUTEX]                 = syscall_futex,
    [KERN_FN_YIELD]                 = syscall_yield,
    [KERN_FN_TLS]                   = syscall_tls,
    [KERN_FN_MUNMAP]                = syscall_munmap,
    [KERN_FN_COPY_HANDLE]           = syscall_copy_handle,
    // Update SYSCALL_COUNT if you add or remove an entry.
    // Also make sure all entrypoint fields are non-NULL.
};

static_assert(ARRAY_ELEMS(syscall_table) == SYSCALL_COUNT, "");

void syscalls_self_check(void)
{
    for (size_t n = 0; n < ARRAY_ELEMS(syscall_table); n++) {
        if (!syscall_table[n])
            panic("Missing syscall entry %zu.\n", n);
    }
}
