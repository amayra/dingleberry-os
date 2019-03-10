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
    MMU_FLAG_A = (1 << 6),      // page accessed bit
    MMU_FLAG_D = (1 << 7),      // page dirty bit

    // Non-RISC-V flags
    MMU_FLAG_RMAP = (1 << 12),  // make mapping revokable
    MMU_FLAG_PS   = (1 << 13),  // see KERNEL_PS_BASE; addresses must fall into
                                // this region
    MMU_FLAG_NEW  = (1 << 14),  // do not allow overwriting existing entries

    // Covnenience
    MMU_FLAG_RW   = MMU_FLAG_R | MMU_FLAG_W,
};

// Low-level CPU virtual memory mapping for a process or the kernel.
struct mmu;

void mmu_init(void);
struct mmu *mmu_alloc(void);
void mmu_free(struct mmu *mmu);

// The intention is to keep a special mmu instance for the kernel half of
// the virtual address space. The kernel address space is the same for all user
// processes, and updates to the kernel mmu instance will be automatically
// reflected in the userspace mmu instances.
struct mmu *mmu_get_kernel(void);

// Establish a virtual memory mapping for address virt in mmu. virt will
// map to the physical address phys.
// The address must be in the suitable range for the mmu, i.e. using a user
// space address will only succeed iff mmu is a userspace mmu, and the
// same for kernel addresses.
//
// This does not try to map "super pages". It only maps PAGE_SIZE units.
// (Rationale: these
// superpages are nifty and allow simpler code in early boot, but other than
// that, they are a relatively obscure optimization. They are more complex to
// handle; e.g. you need to allocate aligned physical addresses, and you would
// need to convert superpages to smaller pages if you change a page mapping
// somewhere in-between.)
//
// If a mapping already exists at a specific position, it will be overwritten.
// Using phys==INVALID_PHY_ADDR will remove a mapping.
// The entire mapping will either succeed, or it does not touch the previous
// state (as far as user-visible). No partial mappings are possible, i.e. it
// will never stop in the middle of it.
//
// MMU_FLAG_RMAP: needed to make mmu_rmap_*() functions work. This requires that
// the physical page was allocated as PAGE_USAGE_USER (which implies it's actual
// RAM, and not device memory or other types of memory).
//
//  mmu: target
//  virt: virtual address in the target; must be aligned to PAGE_SIZE
//  phys: physical memory address; must be aligned to PAGE_SIZE
//  size: size of the mapping; must be exactly PAGE_SIZE
//  flags: MMU_FLAG_* flags
// Returns: success
bool mmu_map(struct mmu *mmu, void *virt, uint64_t phys, size_t size, int flags);

// Change the memory mapping at the given address.
//  virt: exact/page aligned virtual address of a memory page
//  remove_flags: flags to remove (ignores if a to be removed bit wasn't set)
//  add_flags: flags to add
// If the entry was not mapped, then the function fails if add_flags is not 0.
// It also fails if virt is not aligned, or if any of the flags are not allowed.
// Some flags can't be changed: MMU_FLAG_RMAP
// Returns: success
bool mmu_protect(struct mmu *mmu, void *virt, int remove_flags, int add_flags);

// Reverse of mmu_map(). Unmapped entries are returned as success with *phys_out
// set to INVALID_PHY_ADDR. Returns failure only if virt is not a valid mapping
// address (then out_* are set as if it were an unmapped entry). *flags may not
// contain some special flags (such as MMU_FLAG_RMAP).
bool mmu_read_entry(struct mmu *mmu, void *virt, uint64_t *phys_out,
                    size_t *size_out, int *flags_out);

// Remove MMU_FLAG_W from all known MMU_FLAG_RMAP mappings with the given
// physical address. This does not affect mappings which were not mapped with
// MMU_FLAG_RMAP.
void mmu_rmap_mark_ro(uint64_t phys);

// Similar to mmu_rmap_mark_ro(), but remove the mapping completely, instead of
// merely changing permission flags.
// Only the actual owner of the physical page must call this. Otherwise, it may
// create ownership problems, as higher level data structures are likely not
// aware about the unmapping.
void mmu_rmap_unmap(uint64_t phys);

void mmu_switch_to(struct mmu *mmu);

// Return true iff addr/size is generally a valid region within userspace. This
// checks alignment (as allowed by mmu_map()) too.
bool mmu_is_valid_user_region(void *addr, size_t size);

// Assert that the passed mmu is currently set active on this CPU.
#ifndef NDEBUG
#define MMU_ASSERT_CURRENT(mmu) \
    mmu_assert_current((mmu), __FILE__, __LINE__, false)
#else
#define MMU_ASSERT_CURRENT(mmu) do{}while(0)
#endif

void mmu_assert_current(struct mmu *mmu, const char *file, int line, bool inv);
