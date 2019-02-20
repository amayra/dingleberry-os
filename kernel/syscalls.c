#include "kernel.h"
#include "thread.h"

#include <kernel/syscalls.h>

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

static void syscall_thread_create(size_t pc, size_t sp, size_t tp)
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
    // update ASM_SYSCALL_COUNT
};
