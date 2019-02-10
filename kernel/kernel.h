#pragma once

// Dump-it-all place for random garbage.

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libinsanity/minmax.h>

#define panic(...) do {                                                     \
    printf("%s:%d:%s: PANIC: ", __FILE__, __LINE__, __PRETTY_FUNCTION__);   \
    printf(__VA_ARGS__);                                                    \
    abort();                                                                \
} while (0)
