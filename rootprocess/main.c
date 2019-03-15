#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <kernel/api.h>
#include <kernel/stubs.h>

#include <libinsanity/printf.h>

static int64_t g_self_handle;

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

static void other_thread(int num)
{
    printf("other thread\n");
    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread%d)\n", num);
    }
}

static void *kern_mmap(uint64_t dst_handle, void *addr, size_t length,
                          int flags, int handle, uint64_t offset)
{
    return (void *)kern_call6(KERN_FN_MMAP, dst_handle, (uintptr_t)addr,
                              length, flags, handle, offset);
}

int64_t kern_thread_create(int64_t aspace_handle, bool new_aspace)
{
    return kern_call2(KERN_FN_THREAD_CREATE, aspace_handle, new_aspace);
}

int kern_thread_set_context(int64_t thread_handle, struct kern_thread_regs *regs)
{
    return kern_call2(KERN_FN_THREAD_SET_CONTEXT, thread_handle, (uintptr_t)regs);
}

void thread_cr(int num)
{
    size_t stack_size = 4096 * 4;
    void *stack = kern_mmap(KERN_HANDLE_INVALID, (void *)-1, stack_size,
                    KERN_MAP_FORK_COPY | KERN_MAP_PERM_W | KERN_MAP_PERM_R,
                    -1, 0);
    assert(!KERN_MMAP_FAILED(stack));

    struct kern_thread_regs regs = {0};
    regs.regs[2] = (uintptr_t)stack + stack_size;
    regs.regs[10] = num;
    regs.pc = (uintptr_t)other_thread;

    printf("stack: %p-%p\n", stack, (void *)regs.regs[2]);

    int64_t h = kern_thread_create(g_self_handle, false);
    assert(KERN_IS_HANDLE_VALID(h));

    int r = kern_thread_set_context(h, &regs);
    assert(r >= 0);
}

int kern_copy_aspace(int64_t src, int64_t dst, bool emulate_fork)
{
    return kern_call3(KERN_FN_COPY_ASPACE, src, dst, emulate_fork);
}

int kern_close(int64_t handle)
{
    return kern_call1(KERN_FN_CLOSE, handle);
}

int dataseg = 123;

int main(void)
{
    // And this is why we did all this crap.
    printf("Hello world! (From userspace.)\n");

    int freq = kern_call0(KERN_FN_GET_TIMER_FREQ);
    printf("timer freq: %d\n", freq);

    //*(volatile int *)0xdeadbeefd00dull=123;

    thread_cr(2);
    thread_cr(3);

    printf("before: %d\n", dataseg);

    int64_t hfork = kern_thread_create(g_self_handle, true);
    assert(KERN_IS_HANDLE_VALID(hfork));
    int t = kern_copy_aspace(g_self_handle, hfork, true);
    printf("----- fork: %d, %ld\n", t, (long)hfork);
    assert(t >= 0);

    volatile int counter = !t * 40 + 10; // force on stack

    printf("after: %d\n", dataseg);
    if (!t)
        dataseg = counter;
    asm volatile("");
    printf("after overwrite: %d\n", dataseg);

    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread1) fork=%s cnt=%d\n", t?"child":"parent", counter++);
        if (counter == 53 && !t) {
            printf("close forked thread: %d\n", kern_close(hfork));
        }
    }
    return 0;
}

// Uses argument registers as setup by the creator, in this case the kernel.
void crt_init(int64_t self_handle)
{
    g_self_handle = self_handle;
}
