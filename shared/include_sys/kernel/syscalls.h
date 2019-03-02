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

// Parameters:
//  a0: addr, or -1
//      Providing -1 will make the kernel select an arbitrary address (where
//      it doesn't conflict with other current mappings). Otherwise, the
//      behavior is with UNIX MAP_FIXED. The value must be page aligned.
//  a1: length
//      Size of the mapping. Must be page aligned.
//  a2: flags (KERN_MAP_*)
//  a3: handle to object, or -1
//      -1 behaves as with UNIX MAP_ANONYMOUS.
//  a4: offset
//      Offset into the mapped object. Must be page aligned. Must be 0 for
//      anonymous mappings.
#define SYS_MMAP                4

// Access permission bits. If a given combination cannot be provided by the
// hardware, effective permissions may be increased.
#define KERN_MAP_PERM_R         (1 << 0)
#define KERN_MAP_PERM_W         (1 << 1)
#define KERN_MAP_PERM_X         (1 << 2)
// If addr is given, and if it collides with an existing mapping, overwrite it,
// instead of failing. Similar to Linux MAP_FIXED_NOREPLACE (inverted).
// Has no effect if addr==-1.
#define KERN_MAP_OVERWRITE      (1 << 3)
// Mark the mapping as COW. Successful writes to mapping will allocate private
// pages, instead of propagating changes to the mapped object. If the mapped
// object is changed by 3rd parties, the changes are visible only to pages for
// which no private pages were created.
// Note: for anonymous mappings, setting this flag will return an error.
// Similar to UNIX MAP_PRIVATE.
#define KERN_MAP_COW            (1 << 4)
// Create a COW mapping on fork(). There is a subtle difference for mappings
// backed by an object vs. anonymous memory: the latter are essentially
// duplicated, while the former still references the same underlying object,
// but with a duplicated internal handle.
// Mappings without any KERN_MAP_FORK_* flags are not present in the child.
#define KERN_MAP_FORK_COPY      (1 << 5)
// Share the mapping on fork().
#define KERN_MAP_FORK_SHARE     (1 << 6)

#define KERN_MMAP_FAILED(ui) ((intptr_t)(ui) < 0)
