#pragma once

#include <stddef.h>

struct sys_thread_regs {
    // x0-x31 (x0 is ignored; included to avoid confusing register numbers)
    size_t regs[32];
    size_t pc;
};

#define SYS_GET_TIMER_FREQ      0
#define SYS_DEBUG_WRITE_CHAR    1
#define SYS_DEBUG_STOP          2
#define SYS_THREAD_CREATE       3
