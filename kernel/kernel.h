#pragma once

// Dump-it-all place for random garbage.

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libinsanity/minmax.h>

extern uint64_t timer_frequency;

// Preliminary way to allocate kernel virtual memory space. Obviously this needs
// to be replaced by something proper.
extern void *virt_alloc_cur;
extern void *virt_alloc_end;

uint64_t read_timer_ticks(void);

#define panic(...) do {                                                     \
    printf("%s:%d:%s: PANIC: ", __FILE__, __LINE__, __PRETTY_FUNCTION__);   \
    printf(__VA_ARGS__);                                                    \
    abort();                                                                \
} while (0)
