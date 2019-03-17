#pragma once

#include <stddef.h>
#include <stdint.h>

#define SBI_SET_TIMER       0
#define SBI_CONSOLE_PUTCHAR 1

static inline size_t sbi_call4(size_t fn, size_t a0, size_t a1, size_t a2,
                               size_t a3)
{
    register size_t r_a0 asm("a0") = a0;
    register size_t r_a1 asm("a1") = a1;
    register size_t r_a2 asm("a2") = a2;
    register size_t r_a3 asm("a3") = a3;
    register size_t r_a7 asm("a7") = fn;
    asm volatile("ecall"
        : "=r" (r_a0)
        : "r"  (r_a0),
          "r"  (r_a1),
          "r"  (r_a2),
          "r"  (r_a3),
          "r"  (r_a7)
        : "memory");
    return r_a0;
}

#define sbi_call1(fn, a0) \
        sbi_call4(fn, a0, 0,  0,  0)

static inline void sbi_console_putchar(int ch)
{
    sbi_call1(SBI_CONSOLE_PUTCHAR, ch);
}

static inline void sbi_set_timer(uint64_t t)
{
    sbi_call1(SBI_SET_TIMER, t);
}
