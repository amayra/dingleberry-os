#include "kernel.h"

// Note: all syscall_ functions are referenced from syscall_vec in trap.S.

size_t syscall_get_timer_freq(void)
{
    return timer_frequency;
}

size_t syscall_debug_write_char(size_t v)
{
    printf("%c", (char)v);
    return 0;
}

// Pseudo entry for out of bounds syscall values.
size_t syscall_unavailable(size_t nr)
{
    printf("Unknown syscall %"PRIu64".\n", nr);
    return -1;
}
