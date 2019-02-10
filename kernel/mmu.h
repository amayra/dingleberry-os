#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory.h"

enum {
    // Note: these flags coincide with the RISC-V page table flag values.
    // There is no userspace flag - a page is userspace iif its address is
    // below KERNEL_SPACE_BASE.
    MMU_FLAG_R = (1 << 1),      // allow read access
    MMU_FLAG_W = (1 << 2),      // allow write access
    MMU_FLAG_X = (1 << 3),      // allow execution
};

struct aspace;

void aspace_init(void);

// The intention is to keep a special aspace instance for the kernel half of
// the virtual address space. The kernel address space is the same for all user
// processes, and updates to the kernel aspace instance will be automatically
// reflected in the userspace aspace instances.
struct aspace *aspace_get_kernel(void);

// Establish a virtual memory mapping for address virt in aspace. virt will
// map to the physical address phys.
// The address must be in the suitable range for the aspace, i.e. using a user
// space address will only succeed iff aspace is a userspace aspace, and the
// same for kernel addresses.
// This does not try to map "super pages". It only maps PAGE_SIZE units, and
// creates multiple PTEs etc. to satisfy the requested size. (Rationale: these
// superpages are nifty and allow simpler code in early boot, but other than
// that, they are a relatively obscure optimization. They are more complex to
// handle; e.g. you need to allocate aligned physical addresses, and you would
// need to convert superpages to smaller pages if you change a page mapping
// somewhere in-between.)
// If a mapping already exists at a specific position, it will be overwritten.
// Using phys==INVALID_PHY_ADDR will remove a mapping.
// The entire mapping will either succeed, or it does not touch the previous
// state (as far as user-visible). No partial mappings are possible, i.e. it
// will never stop in the middle of it.
//  aspace: target
//  virt: virtual address in the target; must be aligned to PAGE_SIZE
//  phys: physical memory address; must be aligned to PAGE_SIZE
//  size: size of the mapping; must be multiple of PAGE_SIZE
//  flags: MMU_FLAG_* flags
bool aspace_map(struct aspace* aspace, void *virt, uint64_t phys, size_t size,
                int flags);
