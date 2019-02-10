#include "kernel.h"
#include "mmu.h"
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

// Given a valid PTE, return the full physical address in it.
#define PTE_GET_PHYS(pte) (((pte) >> 10) << PAGE_SHIFT)

// Given an aligned physical address, return the address shifted into the
// position as required by PTEs.
#define PTE_FROM_PHYS(phys) (((phys) >> PAGE_SHIFT) << 10)

struct aspace {
    bool is_kernel;
    uint64_t root_pt;
};

static struct slob aspace_slob = SLOB_INITIALIZER(struct aspace);

static struct aspace *aspace_alloc(void)
{
    struct aspace *aspace = slob_allocz(&aspace_slob);
    if (!aspace)
        return NULL;

    aspace->root_pt = page_alloc_phy(1, PAGE_USAGE_PT);
    if (aspace->root_pt == INVALID_PHY_ADDR) {
        slob_free(&aspace_slob, aspace);
        return NULL;
    }

    // Set all entries to unmapped.
    uint64_t *pt = page_phys_to_virt(aspace->root_pt);
    memset(pt, 0, PAGE_SIZE);

    return aspace;
}

static struct aspace *kernel_aspace;

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
        uint64_t *pt = page_phys_to_virt(pt_phy);
        assert(pt);

        size_t entry = MMU_PTE_INDEX(virt, n);
        if (!(pt[entry] & MMU_FLAG_V)) {
            assert(!pt[entry]); // we don't use the spare bits for anything

            // If the leaf PTE to write establishes no mapping, skip page table
            // allocation, as missing PT levels have the same effect.
            if (!(pte & MMU_FLAG_V) && !alloc_pt_only)
                return true;

            uint64_t npt_phys = page_alloc_phy(1, PAGE_USAGE_PT);
            if (npt_phys == INVALID_PHY_ADDR)
                assert(0);

            pt[entry] = PTE_FROM_PHYS(npt_phys) | MMU_FLAG_V;

            // Set all entries to unmapped.
            uint64_t *npt = page_phys_to_virt(npt_phys);
            memset(npt, 0, PAGE_SIZE);

            // Note: I don't think there are any "failure" TLB entries, so no
            // TLB shootdown or flushing of any kind is necessary, at least in
            // a single-CPU system.
        }

        // Next page table entry.
        uint64_t npte = pt[entry];
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
        pte |= PTE_FROM_PHYS(phys);
        pte |= MMU_FLAG_V;
    }

    // Allocate possibly missing page tables first. This means we can provide
    // a "transactional" API that doesn't leave unknown state/partially applied
    // work behind (other than redundant page table allocations, which are
    // harmless).
    // No need to allocate anything if we just overwrite the pte.
    if (pte) {
        for (uint64_t offs = 0; offs < size; offs += PAGE_SIZE) {
            if (!write_pt(aspace, ivirt + offs, 0, true))
                return false; // OOM
        }
    }

    for (uint64_t offs = 0; offs < size; offs += PAGE_SIZE) {
        bool r = write_pt(aspace, ivirt + offs, pte, false);
        assert(r);
    }

    return true;
}
