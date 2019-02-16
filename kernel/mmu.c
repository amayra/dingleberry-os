#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "page_alloc.h"
#include "slob.h"

enum {
    // Following RISC-V
    MMU_FLAG_V = (1 << 0),
    MMU_FLAG_U = (1 << 4),
    MMU_FLAG_G = (1 << 5),
    MMU_FLAG_A = (1 << 6),
    MMU_FLAG_D = (1 << 7),
};

// Physical page number.
#define PPN_FROM_PHYS(phys) ((phys) >> PAGE_SHIFT)

// Given a valid PTE, return the full physical address in it.
#define PTE_GET_PHYS(pte) (((pte) >> 10) << PAGE_SHIFT)

// Given an aligned physical address, return the address shifted into the
// position as required by PTEs.
#define PTE_FROM_PHYS(phys) (PPN_FROM_PHYS(phys) << 10)

static struct slob aspace_slob = SLOB_INITIALIZER(struct aspace);

static struct aspace *kernel_aspace;

static struct {
    struct aspace *head, *tail;
} all_aspaces;

static void sync_with_kernel_aspace(struct aspace *aspace)
{
    if (aspace == kernel_aspace)
        return;

    uint64_t *kpt = page_phys_to_virt(kernel_aspace->root_pt);
    uint64_t *pt = page_phys_to_virt(aspace->root_pt);

    for (size_t n = 256; n < 512; n++) {
        // Should probably flush TLBs for existing entries that were changed.
        pt[n] = kpt[n];
    }
}

// This needs to be called for every aspace whenever the root page table of the
// kernel aspace is changed.
static void sync_all_with_kernel_aspace(void)
{
    for (struct aspace *a = all_aspaces.head; a; a = a->all_aspaces.next)
        sync_with_kernel_aspace(a);
}

struct aspace *aspace_alloc(void)
{
    struct aspace *aspace = slob_allocz(&aspace_slob);
    if (!aspace)
        return NULL;

    aspace->root_pt = page_alloc_phy(1, PAGE_USAGE_PT);
    if (aspace->root_pt == INVALID_PHY_ADDR) {
        slob_free(&aspace_slob, aspace);
        return NULL;
    }

    if (kernel_aspace) {
        sync_with_kernel_aspace(aspace);
    } else {
        // Set all entries to unmapped.
        uint64_t *pt = page_phys_to_virt(aspace->root_pt);
        memset(pt, 0, PAGE_SIZE);
    }

    LL_APPEND(&all_aspaces, aspace, all_aspaces);

    return aspace;
}

void aspace_init(void)
{
    kernel_aspace = aspace_alloc();
    if (!kernel_aspace)
        panic("Could not allocate root page table.\n");

    kernel_aspace->is_kernel = true;
}

struct aspace *aspace_get_kernel(void)
{
    assert(kernel_aspace);
    return kernel_aspace;
}

// Write a leaf page table entry. Tries to allocate required page tables if they
// are not present yet, and the pte V bit is set.
//  alloc_pt_only: if set, don't actually write the pte; only allocate all the
//                 page table levels
//  returns: false iff a page table could not be allocated
static bool write_pt(struct aspace *aspace, uint64_t virt, uint64_t pte,
                     bool alloc_pt_only)
{
    uint64_t pt_phy = aspace->root_pt;

    for (size_t n = 0; n < MMU_NUM_LEVELS - 1; n++) {
        size_t entry = MMU_PTE_INDEX(virt, n);
        uint64_t *pt = page_phys_to_virt(pt_phy);
        assert(pt);

        if (!(pt[entry] & MMU_FLAG_V)) {
            assert(!pt[entry]); // we don't use the spare bits for anything

            // If the leaf PTE to write establishes no mapping, skip page table
            // allocation, as missing PT levels have the same effect.
            if (!(pte & MMU_FLAG_V) && !alloc_pt_only)
                return true;

            uint64_t npt_phys = page_alloc_phy(1, PAGE_USAGE_PT);
            if (npt_phys == INVALID_PHY_ADDR)
                return false;

            // Set all entries to unmapped.
            uint64_t *npt = page_phys_to_virt(npt_phys);
            memset(npt, 0, PAGE_SIZE);

            pt[entry] = PTE_FROM_PHYS(npt_phys) | MMU_FLAG_V;

            // Note: I don't think there are any "failure" TLB entries, so no
            // TLB shootdown or flushing of any kind is necessary, at least in
            // a single-CPU system.

            if (n == 0 && aspace == kernel_aspace)
                sync_all_with_kernel_aspace();
        }

        // Next page table entry.
        uint64_t npte = pt[entry];

        // Superpages are leaf entries on levels above the last, and supporting
        // them (so that you can overmap pages within them) would require
        // allocating a page table like above, then initializing every entry
        // accordingly, then killing TLBs. Very possible and not hard, but don't
        // bother with it for now. Also, it would mean unmap could fail if it
        // tries to split a superpage and no memory is available.
        if (npte & (MMU_FLAG_R | MMU_FLAG_W | MMU_FLAG_X))
            panic("unexpected superpage found");

        pt_phy = PTE_GET_PHYS(npte);
    }

    if (alloc_pt_only)
        return true;

    uint64_t *pt = page_phys_to_virt(pt_phy);
    assert(pt);
    size_t entry = MMU_PTE_INDEX(virt, MMU_NUM_LEVELS - 1);
    pt[entry] = pte;
    // TODO: TLB shootdown
    asm volatile("sfence.vma zero" : : : "memory");

    return true;
}

bool aspace_map(struct aspace* aspace, void *virt, uint64_t phys, size_t size,
                int flags)
{
    assert((flags & (MMU_FLAG_R | MMU_FLAG_W | MMU_FLAG_X)) == flags);

    uint64_t ivirt = (uintptr_t)virt;

    // Promote write-only to read/write, as write-only is "reserved".
    if (flags & MMU_FLAG_W)
        flags |= MMU_FLAG_R;

    if (!size)
        return false; // disallow, makes bound checks slightly simpler

    if ((ivirt & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
        return false; // alignment

    // Must not cross boundaries (including user/kernel split)
    uint64_t min = aspace->is_kernel ? KERNEL_SPACE_BASE : 0;
    uint64_t max = aspace->is_kernel ? UINT64_MAX : MMU_ADDRESS_LOWER_MAX;
    if (ivirt < min)
        return false;
    if (max - ivirt < size - 1)
        return false;

    if (phys != INVALID_PHY_ADDR) {
        if (phys & (PAGE_SIZE - 1))
            return false; // alignment

        if (UINT64_MAX - phys < size- 1)
            return false; // no wraparound
    }

    uint64_t pte = 0;
    if (phys != INVALID_PHY_ADDR) {
        pte |= flags;
        pte |= MMU_FLAG_V;
        if (ivirt < KERNEL_SPACE_BASE)
            pte |= MMU_FLAG_U;
    }

    // Allocate possibly missing page tables first. This means we can provide
    // a "transactional" API that doesn't leave unknown state/partially applied
    // work behind (other than redundant page table allocations, which are
    // harmless).
    // No need to allocate anything if we just overwrite the pte.
    if (pte) {
        for (uint64_t offs = 0; offs < size; offs += PAGE_SIZE) {
            // Note: could skip redundant runs of addresses in leaf page tables
            // each time we know that page table was populated.
            if (!write_pt(aspace, ivirt + offs, 0, true))
                return false; // OOM
        }
    }

    for (uint64_t offs = 0; offs < size; offs += PAGE_SIZE) {
        uint64_t cur_pte = pte ? pte | PTE_FROM_PHYS(phys + offs) : 0;
        bool r = write_pt(aspace, ivirt + offs, cur_pte, false);
        assert(r);
    }

    return true;
}

void aspace_switch_to(struct aspace* aspace)
{
    // Mode 9 = Sv48.
    uint64_t satp = (9ULL << 60) | PPN_FROM_PHYS(aspace->root_pt);
    asm volatile("csrw satp, %0 ; sfence.vma zero"
        : "=r" (satp)
        : "0" (satp)
        : "memory");
}
