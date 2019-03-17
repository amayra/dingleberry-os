#include <assert.h>

#include "syscall.h"

#include <kernel/api.h>
#include <kernel/stubs.h>

#include <libinsanity/printf.h>

#define __panic(...) do {                                                   \
    printf("%s:%d:%s: PANIC: ", __FILE__, __LINE__, __PRETTY_FUNCTION__);   \
    printf(__VA_ARGS__);                                                    \
    kern_call0(KERN_FN_DEBUG_STOP);                                         \
    while(1);                                                               \
} while (0)

#define __panic_ni() __panic("Not implemented.\n")

struct printf_buf {
    char *buf;
    char *dst;
    char *end;
};

void debug_printchar(char c)
{
    kern_call1(KERN_FN_DEBUG_WRITE_CHAR, c);
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
    kern_call0(KERN_FN_DEBUG_STOP);
    while(1);
}

_Noreturn void __assert_fail(const char *expr, const char *file, int line,
                             const char *func)
{
    printf("Assertion failure: %s:%d:%s: %s\n", file, line, func, expr);
    abort();
}

long __emu_SYS_exit_1(long a)
{
    __panic_ni();
}

long __emu_SYS_exit_group_1(long a)
{
    __panic_ni();
}

long __emu_SYS_openat_3(long a, const char *b, long c)
{
    __panic_ni();
}

long __emu_SYS_ppoll_5(struct pollfd *a, long b, struct timespec *c, long d, long e)
{
    __panic_ni();
}

long __emu_SYS_futex_3(volatile void *a, long b, long c)
{
    __panic_ni();
}

long __emu_SYS_futex_4(volatile void *a, long b, long c, long d)
{
    __panic_ni();
}

long __emu_SYS_mmap_6(long a, long b, long c, long d, long e, long f)
{
    __panic_ni();
}

long __emu_SYS_set_tid_address_1(volatile void *a)
{
    // Musl sets this on initialization, and expects it back via gettid in some
    // places. Ignore it for now.
    return 0;
}
