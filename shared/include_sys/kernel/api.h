#pragma once

#include <stddef.h>

struct kern_thread_regs {
    // x0-x31 (x0 is ignored; included to avoid confusing register numbers)
    size_t regs[32];
    size_t pc;
};

// (Often used as magic value to refer to the calling thread.)
#define KERN_HANDLE_INVALID         0

#define KERN_IS_HANDLE_VALID(h) ((h) > KERN_HANDLE_INVALID)

#define KERN_FN_GET_TIMER_FREQ      0
#define KERN_FN_DEBUG_WRITE_CHAR    1
#define KERN_FN_DEBUG_STOP          2

// a0: handle
// returns: error code; can fail only on invalid handles
#define KERN_FN_CLOSE               3

// a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
// a1: if 1, ignore a0 and create a new address space
//     (rationale: processes maybe won't know their own thread handle? this
//      won't really work, so it'll be changed again)
// returns: thread handle; invalid handle on error
#define KERN_FN_THREAD_CREATE       4

// Parameters:
//  a0: thread handle
//  a1: pointer to sys_thread_regs
//  returns: error code
#define KERN_FN_THREAD_SET_CONTEXT  5

// Parameters:
//  a0: thread handle for address space (KERN_HANDLE_INVALID: calling thread)
//  a1: addr, or -1
//      Providing -1 will make the kernel select an arbitrary address (where
//      it doesn't conflict with other current mappings). Otherwise, the
//      behavior is with UNIX MAP_FIXED. The value must be page aligned.
//  a2: length
//      Size of the mapping. Must be page aligned.
//  a3: flags (KERN_MAP_*)
//  a4: handle to object, or -1
//      -1 behaves as with UNIX MAP_ANONYMOUS.
//  a5: offset
//      Offset into the mapped object. Must be page aligned. Must be 0 for
//      anonymous mappings.
//  returns: pointer, invalid pointer on error (see KERN_MMAP_FAILED())
#define KERN_FN_MMAP                6

// Access permission bits. If a given combination cannot be provided by the
// hardware, effective permissions may be increased.
#define KERN_MAP_PERM_R             (1 << 0)
#define KERN_MAP_PERM_W             (1 << 1)
#define KERN_MAP_PERM_X             (1 << 2)
// If addr is given, and if it collides with an existing mapping, overwrite it,
// instead of failing. Similar to Linux MAP_FIXED_NOREPLACE (inverted).
// Has no effect if addr==-1.
#define KERN_MAP_OVERWRITE          (1 << 3)
// Mark the mapping as COW. Successful writes to mapping will allocate private
// pages, instead of propagating changes to the mapped object. If the mapped
// object is changed by 3rd parties, the changes are visible only to pages for
// which no private pages were created.
// Note: for anonymous mappings, setting this flag will return an error.
// Similar to UNIX MAP_PRIVATE.
#define KERN_MAP_COW                (1 << 4)
// Create a COW mapping on fork() (i.e. whatever calls KERN_FN_COPY_ASPACE).
// There is a subtle difference for mappings backed by an object vs. anonymous
// memory: the latter are essentially duplicated, while the former still
// references the same underlying object, but with a duplicated internal handle.
// Mappings without any KERN_MAP_FORK_* flags are not present in the child.
#define KERN_MAP_FORK_COPY          (1 << 5)
// Share the mapping on fork().
#define KERN_MAP_FORK_SHARE         (1 << 6)

#define KERN_MMAP_FAILED(ui) ((intptr_t)(ui) < 0)

// Performs a COW copy of all address space mappings. Returns failure if target
// address space is not empty.
// Note that a2 is a helper for implementing fork(). Strictly speaking, the
// parameter is redundant to existing mechanism, and could be implemented
// entirely in userspace. It's slightly simpler in kernel space though (no need
// to write asm that references the syscall ABI).
// Parameters:
//  a0: source address space (KERN_HANDLE_INVALID: calling thread)
//  a1: target address space
//  a2: 0 or 1; if set to 1, then set a1 to a copy of the caller thread register
//      context; the target thread will pretend to return with 1 as error code
//  returns: error code (always 0 on success)
#define KERN_FN_COPY_ASPACE         7
