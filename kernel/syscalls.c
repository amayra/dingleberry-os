#include "kernel.h"
#include "thread.h"

// Note: all syscall_ functions are referenced from syscall_vec in trap.S.

// Pseudo entry for out of bounds syscall values.
size_t syscall_unavailable(size_t nr)
{
    printf("Unknown syscall %"PRIu64".\n", nr);
    return -1;
}

size_t syscall_get_timer_freq(void)
{
    return timer_frequency;
}

size_t syscall_debug_write_char(size_t v)
{
    printf("%c", (char)v);
    return 0;
}

void syscall_debug_stop(void)
{
    panic("User stop.\n");
}


void syscall_thread_create(size_t pc, size_t sp, size_t tp)
{
    struct aspace *aspace = thread_get_aspace(thread_current());
    struct asm_regs regs = {
        .regs = {
            [2] = sp,
            [4] = tp,
        },
        .pc = pc,
        .status = 0,
    };
    struct thread *t = thread_create(aspace, &regs);
    assert(t);
    printf("user created thread: %p\n", t);
}
