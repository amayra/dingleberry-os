#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <kernel/syscalls.h>

#include <libinsanity/printf.h>

int foo[4097];
int foo2[4097]={1};
const int foo3[4097]={2};
const int foo4[4097]={3};

struct printf_buf {
    char *buf;
    char *dst;
    char *end;
};

void debug_printchar(char c)
{
    register uintptr_t r asm("a0") = c;
    asm volatile("li a7, %[id] ; ecall"
        : "=r" (r)                                  // clobber a0
        : [id]"i" (SYS_DEBUG_WRITE_CHAR), "r" (r)
        : "a1", "a2", "a3", "a4", "a5", "a6", "a7",
          "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "memory");
}

static void print_cb(void *ctx)
{
    struct printf_buf *buf = ctx;
    for (char *s = buf->buf; s < buf->dst; s++)
        debug_printchar(*s);
    buf->dst = buf->buf;
}

int printf(const char *__restrict fmt , ...)
{
    int ret;
    va_list va;
    va_start(va, fmt);

    char buffer[1]; // output each character immediately for now
    struct printf_buf buf = {
        .buf = buffer,
        .dst = buffer,
        .end = buffer + sizeof(buffer),
    };
    ret = lin_bprintf(&buf.dst, &buf.end, print_cb, &buf, fmt, va);
    print_cb(&buf); // flush

    va_end(va);
    return ret;
}

_Noreturn void abort(void)
{
    printf("abort() called. Halting.\n");
    while(1)
        asm volatile("wfi");
}

_Noreturn void __assert_fail(const char *expr, const char *file, int line,
                             const char *func)
{
    printf("Assertion failure: %s:%d:%s: %s\n", file, line, func, expr);
    abort();
}

static void other_thread(void)
{
    printf("other thread\n");
    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread2)\n");
    }
}

void thread_cr(void)
{
    static char stack[4096];

    register uintptr_t a0 asm("a0") = (uintptr_t)other_thread;
    register uintptr_t a1 asm("a1") = (uintptr_t)(stack + sizeof(stack));
    register uintptr_t a2 asm("a2") = 0;
    register uintptr_t a7 asm("a7") = SYS_THREAD_CREATE;
    asm volatile("ecall"
        : "=r" (a0),                                // clobber a0
          "=r" (a1),                                // clobber a1
          "=r" (a2),                                // clobber a2
          "=r" (a7)                                 // clobber a7
        : "r" (a0),
          "r" (a1),
          "r" (a2),
          "r" (a7)
        : "a3", "a4", "a5", "a6",
          "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "memory");
}

int main(void)
{
    // And this is why we did all this crap.
    printf("Hello world! (From userspace.)\n");

    register uintptr_t a0 asm("a0") = 0;
    register uintptr_t a7 asm("a7") = SYS_GET_TIMER_FREQ;
    asm volatile("ecall"
        : "=r" (a0), "=r" (a7)
        : "r" (a0), "r" (a7)
        : "a1", "a2", "a3", "a4", "a5", "a6",
          "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "memory");
    printf("timer freq: %zd\n", a0);

    //*(volatile int *)0xdeadbeefd00dull=123;

    thread_cr();

    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread1)\n");
    }
    return 0;
}
