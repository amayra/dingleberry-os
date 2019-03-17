#pragma once

#include <stdint.h>

// There is an instance of this struct For every page of physical RAM.
struct phys_page {
    uint8_t usage;      // enum page_usage cast to uint8_t
    uint8_t pa_flags;   // internal to page_alloc.c; PAGE_FLAG_* bit field.

    // Contents depend on usage. This field is separate from .u to save some
    // bytes of memory (as alignment frees up some space at this position).
    // Meaning:
    //  PAGE_USAGE_USER: VM_PHYS_PAGE_FLAG_*
    uint16_t u_flags;


    // Contents depend on usage.
    union {
        // PAGE_USAGE_USER (virtual memory)
        struct {
            // List of all PTEs mapping this page.
            // Note: the pte_list does _not_ cover all uses of the physical
            //       page. A physical page could be used even if unmapped.
            //       The kernel mapping is also not part of it.
            struct mmu_pte_link *pte_list;
            // Logical usage count (number of vm_resident structs using this).
            uint32_t vm_refcount;
            // VM_PHYS_PAGE_FLAG_*
            uint32_t vm_flags;
            // Futex waiters for all addresses that fall within this page. (You
            // could optimize this for space by stuffing it into pte_list as a
            // magic entry. You could also just use a global hashtable for all
            // futexes [along with per-addressspace hashtables if a certain flag
            // is set, because Linux figured out a global hashtable isn't so
            // great], but screw that.)
            struct futex_waiter *futex_waiters;
        } user;
    } u;
};

// Return page into which the address points to. Returns NULL for unmanaged
// addresses (such as device memory).
struct phys_page *phys_page_get(uint64_t phys_addr);
