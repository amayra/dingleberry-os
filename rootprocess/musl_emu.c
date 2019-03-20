#define _GNU_SOURCE

#include <assert.h>

#include "pthread_impl.h"
#include "syscall.h"
#include "stdio_impl.h"
#include "libc.h"
#include "lock.h"
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>

#include <kernel/api.h>
#include <kernel/stubs.h>

#include <libinsanity/printf.h>

void __emu_init(int64_t self_handle);

#define SECOND_NS (1000ULL * 1000 * 1000)

// Kernel TLS slots (KERN_FN_TLS) and their uses.
#define KTLS_CLEARTID   0
#define KTLS_HANDLE     1

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

static size_t ktls_get(size_t index)
{
    if (index >= KERN_TLS_NUM)
        __panic("invalid TLS index\n");
    return kern_call4(KERN_FN_TLS, KERN_HANDLE_INVALID, KERN_TLS_GET, index, 0);
}

static void ktls_set(int64_t handle, size_t index, size_t val)
{
    if ((long)kern_call4(KERN_FN_TLS, handle, KERN_TLS_SET, index, val) < 0)
        __panic("TLS set failed\n");
}

long __emu_SYS_openat_3(long a, const char *b, long c)
{
    __panic_ni();
}

long __emu_SYS_ppoll_5(struct pollfd *a, long b, struct timespec *c, long d, long e)
{
    __panic_ni();
}

long __emu_SYS_nanosleep_2(const struct timespec *a, struct timespec *b)
{
    if (a->tv_nsec < 0 || a->tv_nsec >= SECOND_NS || a->tv_sec < 0)
        return -EINVAL;

    struct kern_timespec ts;
    if (kern_get_time(&ts) < 0)
        return -ENOSYS;

    struct kern_timespec dst = ts;
    dst.sec += a->tv_sec;
    dst.nsec += a->tv_nsec;
    if (dst.nsec >= SECOND_NS) {
        dst.nsec -= SECOND_NS;
        dst.sec += 1;
    }

    // Dummy futex call for timer.
    uint32_t dummy = 0;
    int r = kern_call4(KERN_FN_FUTEX, KERN_FUTEX_WAIT, (uintptr_t)&dst,
                       (uintptr_t)&dummy, 0);

    // With r==0, it would mean we got a sporadic wakeup... well whatever.
    if (r < 1)
        return r == 0 ? -EINTR : -EINVAL;

    // Compute time we actually waited.

    struct kern_timespec ts2;
    if (kern_get_time(&ts2) < 0)
        return -ENOSYS;

    ts2.sec -= ts.sec;
    if (ts2.nsec < ts.nsec) {
        ts2.sec -= 1;
        ts2.nsec = ts2.nsec + SECOND_NS - ts.nsec;
    } else {
        ts2.nsec -= ts.nsec;
    }

    b->tv_sec = ts2.sec;
    b->tv_nsec = ts2.nsec;

    return 0;
}

long __emu_SYS_clock_gettime_2(long a, struct timespec *b)
{
    // Ignore the clock argument.
    struct kern_timespec ts;
    if (kern_get_time(&ts) < 0)
        return -ENOSYS;
    b->tv_nsec = ts.nsec;
    b->tv_sec = ts.sec;
    return 0;
}

long __emu_SYS_gettimeofday_2(void *a, void *b)
{
    // We never need this. musl prefers clock_gettime and falls back to this.
    return -ENOSYS;
}

long __emu_SYS_futex_3(volatile void *a, long b, long c)
{
    return __emu_SYS_futex_4(a, b, c, 0);
}

long __emu_SYS_futex_4(volatile void *a, long b, long c, void *d)
{
    switch (b & ~(unsigned)FUTEX_PRIVATE) {
    case FUTEX_WAIT: {
        struct kern_timespec ts;
        struct kern_timespec *pts = NULL;
        if (d) {
            if (kern_get_time(&ts) < 0)
                return -ENOSYS;

            struct timespec *timeout = d;
            ts.sec += timeout->tv_sec;
            ts.nsec += timeout->tv_nsec;
            if (ts.nsec >= SECOND_NS) {
                ts.nsec -= SECOND_NS;
                ts.sec += 1;
            }
            pts = &ts;
        }

        int r = kern_call4(KERN_FN_FUTEX, KERN_FUTEX_WAIT, (uintptr_t)pts,
                           (uintptr_t)a, c);
        if (r == 1)
            return 0;
        if (r == 0)
            return -ETIMEDOUT;
        return -EINVAL; // inaccurate
    }
    case FUTEX_WAKE: {
        int r = kern_call4(KERN_FN_FUTEX, KERN_FUTEX_WAKE, 0, (uintptr_t)a, c);
        if (r >= 0)
            return r;
        return -EINVAL; // inaccurate
    }
    }

    return -ENOSYS;
}

long __emu_SYS_mmap_6(void *addr, long length, long prot, long flags, long fd,
                      long offset)
{
    int kflags = 0;

    if (!(flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)))
        addr = (void *)-1;

    if (flags & MAP_FIXED)
        kflags |= KERN_MAP_OVERWRITE;

    if (fd >= 0)
        return -ENOSYS; // unsupported

    if (!(flags & MAP_ANONYMOUS))
        return -ENOSYS;

    if (flags & MAP_SHARED) {
        kflags |= KERN_MAP_FORK_SHARE;
    } else {
        kflags |= KERN_MAP_FORK_COPY;
    }

    if (prot & PROT_READ)
        kflags |= KERN_MAP_PERM_R;
    if (prot & PROT_WRITE)
        kflags |= KERN_MAP_PERM_W;
    if (prot & PROT_EXEC)
        kflags |= KERN_MAP_PERM_X;

    void *r = kern_mmap(KERN_HANDLE_INVALID, addr, length, kflags, -1, offset);
    return KERN_MMAP_FAILED(r) ? -EINVAL : (long)r;
}

long __emu_SYS_munmap_2(void *a, long b)
{
    return kern_munmap(KERN_HANDLE_INVALID, a, b) < 0 ? -EINVAL : 0;
}

long __emu_SYS_mprotect_3(long addr, long length, long prot)
{
    unsigned kflags = 0;

    if (prot & PROT_READ)
        kflags |= KERN_MAP_PERM_R;
    if (prot & PROT_WRITE)
        kflags |= KERN_MAP_PERM_W;
    if (prot & PROT_EXEC)
        kflags |= KERN_MAP_PERM_X;

    return kern_mprotect(KERN_HANDLE_INVALID, (void *)addr, length,
                         KERN_MAP_PERM_R | KERN_MAP_PERM_W | KERN_MAP_PERM_X,
                         kflags) < 0 ? -EINVAL : 0;
}

long __emu_SYS_set_robust_list_2(void *a, long b)
{
    __panic_ni();
}

long __emu_SYS_rt_sigprocmask_4(long a, const void *b, void *c, long d)
{
    return 0; // ignore; signals are not supported
}

long __emu_SYS_set_tid_address_1(volatile void *a)
{
    ktls_set(KERN_HANDLE_INVALID, KTLS_CLEARTID, (uintptr_t)a);
    return 0;
}

// Reminder: this is the Linux syscall for _thread_ exit.
long __emu_SYS_exit_1(long a)
{
    volatile int *ctid = (void *)ktls_get(KTLS_CLEARTID);
    int64_t h = ktls_get(KTLS_HANDLE);

    // musl should be calling this only for non-detached threads, which always
    // use this. Detached threads use __unmapself() instead.
    assert(ctid);
    assert(KERN_IS_HANDLE_VALID(h));

    // Wake and exit thread without touching stack. The caller of pthread_join()
    // could really terminate the thread itself (and that would be much simpler),
    // but Linux/musl don't work this way. musl will unmap the stack as soon as
    // it thinks the thread is gone, so the thread must not be accessed, as the
    // thread might actually terminate a moment later.
    // Also this looks pretty painful because I didn't want to add an "asm" mode
    // to api.h; so this is inline asm, and all constants are passed as explicit
    // parameters. In addition, gcc's asm constraints are brainfucked.
    register int64_t r_h __asm("a0") = h;
    register volatile int *r_ctid __asm("a2") = ctid;
    __asm volatile("mv s0, a0\n"            // copy to a syscall-saved register
                   "sd zero, (a2)\n"        // clear ctid
                   "li a7, %[futex_fn]\n"
                   "li a0, %[futex_wake]\n"
                   "li a1, 0\n"
                   "li a3, -1\n"
                   "ecall\n"                // futex wakeup on ctid
                   "li a7, %[close_fn]\n"
                   "mv a0, s0\n"
                   "ecall\n"                // exit this thread
                   "1:\n"
                   "li a7, %[stop_fn]\n"
                   "ecall\n"                // unreachable
                   "j 1b\n"
                   :
                   : [h] "r" (r_h),
                     [ctid] "r" (r_ctid),
                     [futex_fn] "i" (KERN_FN_FUTEX),
                     [futex_wake] "i" (KERN_FUTEX_WAKE),
                     [close_fn] "i" (KERN_FN_CLOSE),
                     [stop_fn] "i" (KERN_FN_DEBUG_STOP)
                   : "memory");
    while(1);
}

void __unmapself(void *p, size_t s)
{
    volatile int *ctid = (void *)ktls_get(KTLS_CLEARTID);
    int64_t h = ktls_get(KTLS_HANDLE);

    // musl should be calling this only for detached threads, which never use this.
    assert(!ctid);
    assert(KERN_IS_HANDLE_VALID(h));

    // Unmap stack and then exit thread without touching stack.
    // See SYS_exit for a comment on asm mess.
    register int64_t r_h __asm("a0") = h;
    register void *r_p __asm("a1") = p;
    register size_t r_s __asm("a2") = s;
    __asm volatile("mv s0, a0\n"            // copy to a syscall-saved register
                   "li a7, %[munmap_fn]\n"
                   "ecall\n"                // unmap stack
                   "li a7, %[close_fn]\n"
                   "mv a0, s0\n"
                   "ecall\n"                // exit this thread
                   "1:\n"
                   "li a7, %[stop_fn]\n"
                   "ecall\n"                // unreachable
                   "j 1b\n"
                   :
                   : [h] "r" (r_h),
                     "r" (r_p),
                     "r" (r_s),
                     [munmap_fn] "i" (KERN_FN_MUNMAP),
                     [close_fn] "i" (KERN_FN_CLOSE),
                     [stop_fn] "i" (KERN_FN_DEBUG_STOP)
                   : "memory");
    while(1);

}

long __emu_SYS_exit_group_1(long a)
{
    // There's no exit syscall, so we can only deal with 1 thread.
    if (a_fetch_add(&libc.threads_minus_1, 0))
        __panic_ni();

    int64_t h = ktls_get(KTLS_HANDLE);
    assert(KERN_IS_HANDLE_VALID(h));
    kern_close(h);
    __panic("unreachable\n");
}

long __emu_SYS_fork_0(void)
{
    int64_t hfork = kern_thread_create(KERN_HANDLE_INVALID, true);
    if (!KERN_IS_HANDLE_VALID(hfork))
        return -EAGAIN;

    // New process needs at least the new thread handle, as the musl-emu
    // currently uses that for locks and to terminate threads.
    int64_t new_hself = kern_copy_handle(hfork, hfork);
    if (!KERN_IS_HANDLE_VALID(new_hself)) {
        kern_close(hfork);
        return -EAGAIN;
    }

    int t = kern_copy_aspace(KERN_HANDLE_INVALID, hfork, true);
    if (t < 0) {
        kern_close(hfork);
        return -EAGAIN;
    }

    if (t == 1) {
        // The forked "child". Need to update the musl TIDs.
        ktls_set(new_hself, KTLS_HANDLE, new_hself);
        pthread_t self = __pthread_self();
        self->tid = new_hself;
        return 0;
    } else {
        // The parent. Currently, there are no PIDs. Should we just return the
        // child handle? Thanks to our dumb refcounting idea for thread handles,
        // this would make the child unable to stop execution, so just return
        // a dummy value until there is a proper concept for thread/process
        // management.
        kern_close(hfork);
        return 2; // dummy PID
    }
}

long __emu_SYS_gettid_0(void)
{
    // TODO: musl uses this as "owner" field for mutexes and such. This doesn't
    //       work for process shared mutexes, because thread handles are
    //       process local.
    return ktls_get(KTLS_HANDLE);
}

// Emulate ridiculous backwards Linux garbage (what the fuck were they smoking?).
// Further args in varargs: ptid, tls, ctid
int __clone(int (*ep)(void *), void *stack, int flags, void *arg, ...)
{
    int thread_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                       CLONE_THREAD | CLONE_SYSVSEM;

    if ((flags & thread_flags) != thread_flags)
        return -ENOSYS; // maybe a real fork?
    flags &= ~(unsigned)thread_flags;

    int *ptid = NULL;
    void *tls = NULL;
    volatile int *ctid = NULL;

    // Note: screw garbage platforms which require va_end().
    va_list ap;
    va_start(ap, arg);

    if (flags & CLONE_PARENT_SETTID) {
        ptid = va_arg(ap, int *);
        flags &= ~(unsigned)CLONE_PARENT_SETTID;
    }

    if (flags & CLONE_SETTLS) {
        tls = va_arg(ap, char *); // yep, it's char*; makes no sense, but.
        flags &= ~(unsigned)CLONE_SETTLS;
    }

    if (flags & CLONE_CHILD_CLEARTID) {
        ctid = va_arg(ap, volatile int *);
        flags &= ~(unsigned)CLONE_CHILD_CLEARTID;
    }

    flags &= ~(unsigned)CLONE_DETACHED; // no effect on Linux

    if (flags)
        return -ENOSYS;

    uintptr_t gp;
    __asm("mv %0, gp" : "=r" (gp));

    struct kern_thread_regs regs = {0};
    regs.regs[2] = (uintptr_t)stack;
    regs.regs[3] = gp;
    regs.regs[4] = (uintptr_t)tls;
    regs.regs[10] = (uintptr_t)arg;
    regs.pc = (uintptr_t)ep;

    int64_t h = kern_thread_create(KERN_HANDLE_INVALID, false);
    if (!KERN_IS_HANDLE_VALID(h))
        return -EAGAIN; // out of resources

    ktls_set(h, KTLS_HANDLE, h);

    if (ptid)
        *ptid = h; // same as gettid()

    if (ctid)
        ktls_set(h, KTLS_CLEARTID, (uintptr_t)ctid);


    // This "starts" the thread.
    if (kern_thread_set_context(h, &regs) < 0)
        return -EINVAL;

    return 0;
}

void __emu_init(int64_t self_handle)
{
    ktls_set(self_handle, KTLS_HANDLE, self_handle);
}
