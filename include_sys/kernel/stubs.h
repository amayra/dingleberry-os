#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api.h"

static inline size_t kern_call8(size_t fn, size_t a0, size_t a1, size_t a2,
                                size_t a3, size_t a4, size_t a5, size_t a6,
                                size_t a7)
{
    register size_t r_a0 __asm("a0") = a0;
    register size_t r_a1 __asm("a1") = a1;
    register size_t r_a2 __asm("a2") = a2;
    register size_t r_a3 __asm("a3") = a3;
    register size_t r_a4 __asm("a4") = a4;
    register size_t r_a5 __asm("a5") = a5;
    register size_t r_a6 __asm("a6") = a6;
    register size_t r_a7 __asm("a7") = a7;
    register size_t r_t6 __asm("t6") = fn;
    __asm volatile("ecall"
        : "=r" (r_a0),
          // Clobber the rest.
          "=r" (r_a1),
          "=r" (r_a2),
          "=r" (r_a3),
          "=r" (r_a4),
          "=r" (r_a5),
          "=r" (r_a6),
          "=r" (r_a7),
          "=r" (r_t6)
        : "r"  (r_a0),
          "r"  (r_a1),
          "r"  (r_a2),
          "r"  (r_a3),
          "r"  (r_a4),
          "r"  (r_a5),
          "r"  (r_a6),
          "r"  (r_a7),
          "r"  (r_t6)
        // Clobber all other non-callee-saved/immutable registers.
        : "ra", "t0", "t1", "t2", "t3", "t4", "t5", "memory");
    return r_a0;
}

// These waste some code size, because they will load 0 into the unused
// argument registers, but it saves some typing and makes the source code
// more compact.
#define kern_call0(fn) \
        kern_call7(fn, 0,  0,  0,  0,  0,  0,  0)
#define kern_call1(fn, a0) \
        kern_call7(fn, a0, 0,  0,  0,  0,  0,  0)
#define kern_call2(fn, a0, a1) \
        kern_call7(fn, a0, a1, 0,  0,  0,  0,  0)
#define kern_call3(fn, a0, a1, a2) \
        kern_call7(fn, a0, a1, a2, 0,  0,  0,  0)
#define kern_call4(fn, a0, a1, a2, a3) \
        kern_call7(fn, a0, a1, a2, a3, 0,  0,  0)
#define kern_call5(fn, a0, a1, a2, a3, a4) \
        kern_call7(fn, a0, a1, a2, a3, a4, 0,  0)
#define kern_call6(fn, a0, a1, a2, a3, a4, a5) \
        kern_call7(fn, a0, a1, a2, a3, a4, a5, 0)
#define kern_call7(fn, a0, a1, a2, a3, a4, a5, a6) \
        kern_call8(fn, a0, a1, a2, a3, a4, a5, a6, 0)

static inline int kern_get_time(struct kern_timespec *t)
{
    return kern_call1(KERN_FN_GET_TIME, (uintptr_t)t);
}

static inline void *kern_mmap(kern_handle dst, void *addr, size_t length,
                              int flags, kern_handle handle, uint64_t offset)
{
    return (void *)kern_call6(KERN_FN_MMAP, dst, (uintptr_t)addr,
                              length, flags, handle, offset);
}

static inline int kern_munmap(kern_handle dst, void *addr, size_t length)
{
    return kern_call3(KERN_FN_MUNMAP, dst, (uintptr_t)addr, length);
}

static inline int kern_mprotect(kern_handle dst, void *addr, size_t length,
                                unsigned remove_flags, unsigned add_flags)
{
    return kern_call5(KERN_FN_MPROTECT, dst, (uintptr_t)addr, length,
                      remove_flags, add_flags);
}

static inline kern_handle kern_thread_create(kern_handle aspace, bool new_aspace)
{
    return kern_call2(KERN_FN_THREAD_CREATE, aspace, new_aspace);
}

static inline int kern_thread_set_context(kern_handle thread,
                                          struct kern_thread_regs *regs)
{
    return kern_call2(KERN_FN_THREAD_SET_CONTEXT, thread, (uintptr_t)regs);
}

static inline int kern_copy_aspace(kern_handle src, kern_handle dst,
                                   bool emulate_fork)
{
    return kern_call3(KERN_FN_COPY_ASPACE, src, dst, emulate_fork);
}

static inline int kern_close(kern_handle handle)
{
    return kern_call1(KERN_FN_CLOSE, handle);
}

static inline kern_handle kern_copy_handle(kern_handle dst, kern_handle handle)
{
    return kern_call2(KERN_FN_COPY_HANDLE, dst, handle);
}

static inline void kern_yield(void)
{
    kern_call0(KERN_FN_YIELD);
}
