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

// Preliminary way to allocate kernel virtual memory space. Obviously this needs
// to be replaced by something proper.
extern void *virt_alloc_cur;
extern void *virt_alloc_end;

#define panic(...) do {                                                     \
    printf("%s:%d:%s: PANIC: ", __FILE__, __LINE__, __PRETTY_FUNCTION__);   \
    printf(__VA_ARGS__);                                                    \
    abort();                                                                \
} while (0)

// Exclude pointer types.
#define REQUIRE_ZERO(x) sizeof(int[(x) ? -1 : 1])
#define REQUIRE_SAME_TYPES(a, b) \
    REQUIRE_ZERO(__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))
#define REQUIRE_ARRAY(x) REQUIRE_SAME_TYPES((x), &(x)[0])

#define ARRAY_ELEMS(x) (sizeof(x) / sizeof((x)[0]) + 0 * REQUIRE_ARRAY(x))

/* Number of entries in syscall_table[]. */
#define SYSCALL_COUNT 9

void syscalls_self_check(void);
