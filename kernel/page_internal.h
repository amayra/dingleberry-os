#pragma once

#include <stdint.h>

// There is an instance of this struct For every page of physical RAM.
struct phys_page {
    uint8_t usage;      // enum page_usage cast to uint8_t
    uint8_t pa_flags;   // internal to page_alloc.c; PAGE_FLAG_* bit field.

    // Contents depend on usage.
    union {
        // PAGE_USAGE_USER (virtual memory)
        struct {
            // List of all PTEs mapping this page.
            // Note: the pte_list does _not_ cover all uses of the physical
            //       page. A physical page could be used even if unmapped.
            //       The kernel mapping is also not part of it.
            struct mmu_pte_link *pte_list;
            // Logical usage count. (To be used for COW.)
            uint64_t vm_refcount;
        } user;
    } u;
};

// Return page into which the address points to. Returns NULL for unmanaged
// addresses (such as device memory).
struct phys_page *phys_page_get(uint64_t phys_addr);
