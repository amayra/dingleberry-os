#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory.h"

// Per-page usage flags. Beyond marking a page as free or used, this is used
// for debugging only.
enum page_usage {
    PAGE_USAGE_FREE = 0,
    PAGE_USAGE_RESERVED,
    PAGE_USAGE_KERNEL,
    PAGE_USAGE_GENERAL,
    PAGE_USAGE_GENERAL_2,
    PAGE_USAGE_GENERAL_3,
    PAGE_USAGE_SLOBBY,

    // Invalid value
    PAGE_USAGE_COUNT
};

// Add physical range of potentially useable RAM. Called on early boot, so the
// caller might mark ranges as reserved later on. Return success.
bool page_alloc_add_ram(uint64_t base_phy, size_t size);

// Mark physical range of RAM as reserved. Called on early boot to exclude our
// own binary, or firmware reserved memory.
// This tolerates unaligned addresses/sizes, and expands them to page boundaries.
// Has no effect on unknown region, including if it was called before
// page_alloc_add_ram(), even if the regions overlap.
void page_alloc_mark(uint64_t base_phy, size_t size, enum page_usage usage);

// Allocate num_pages of memory. Return INVALID_ADDR on failure. When freeing
// pages, the pointer, page number, and usage must be the same.
// usage is for debugging.
uint64_t page_alloc_phy(size_t num_pages, enum page_usage usage);
void page_free_phy(uint64_t addr, size_t num_pages);

// Convert the given physical address to a kernel virtual address, using the
// KERNEL_PHY_BASE range. If the physical address is outside of the range,
// NULL is returned. The latter never happens for addresses returned by
// page_alloc_phy(), but page_phys_to_virt() can/could be used for other
// purposes.
void *page_phys_to_virt(uint64_t addr);

// size in bytes (rounded to pages), returns address put though
// page_phys_to_virt(). Otherwise same semantics as page_*_phy().
void *page_alloc(size_t size, enum page_usage usage);
void page_free(void *addr, size_t size);

void page_alloc_debug_dump(void);
