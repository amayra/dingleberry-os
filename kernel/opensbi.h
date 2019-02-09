#pragma once

#include <stdint.h>

#define SBI_CONSOLE_PUTCHAR 1

static inline void sbi_console_putchar(int ch)
{
    // God, with all this constraint complexity, why does gcc need shitty hacks
    // like this?
    register uintptr_t r asm("a0") = ch;
    asm volatile("li a7, %[id] ; ecall"
        : "=r" (r)                                  // clobber a0
        : [id]"i" (SBI_CONSOLE_PUTCHAR), "r" (r)
        : "a7");
}
