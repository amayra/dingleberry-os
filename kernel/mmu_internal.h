#pragma once

#include "kernel.h"

struct mmu {
    bool is_kernel;
    uint64_t root_pt;

    struct {
        struct thread *head, *tail;
    } owners;

    struct {
        struct mmu *prev, *next;
    } all_mmus;
};

// We need to be able to easily change the permissions of all mappings of a
// physical page (or revoke all mappings). This forms a singly-linked list for
// each page (struct phys_page.pte_list) that includes most mappings of a page.
// Note that this makes changing a single, specific mapping O(n) for n mappings,
// but we hope n is small.
struct mmu_pte_link {
    struct mmu *mmu;            // owner of the mapping
    void *map_addr;             // virtual address of the mapping PTE
    struct mmu_pte_link *next;  // singly linked list
};
