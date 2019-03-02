#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "slob.h"

enum {
    // Following RISC-V
    MMU_FLAG_V = (1 << 0),
    MMU_FLAG_U = (1 << 4),
};

// Physical page number.
#define PPN_FROM_PHYS(phys) ((phys) >> PAGE_SHIFT)

// Given a valid PTE, return the full physical address in it.
#define PTE_GET_PHYS(pte) (((pte) >> 10) << PAGE_SHIFT)

// Given an aligned physical address, return the address shifted into the
// position as required by PTEs.
#define PTE_FROM_PHYS(phys) (PPN_FROM_PHYS(phys) << 10)

static struct slob mmu_slob = SLOB_INITIALIZER(struct mmu);
static struct slob pte_link_slob = SLOB_INITIALIZER(struct mmu_pte_link);

static struct mmu *kernel_mmu;

static struct {
    struct mmu *head, *tail;
} all_mmus;

static void flush_tlb_all(void)
{
    asm volatile("sfence.vma zero, zero" : : : "memory");
}

static void sync_with_kernel_mmu(struct mmu *mmu)
{
    if (mmu == kernel_mmu)
        return;

    uint64_t *kpt = page_phys_to_virt(kernel_mmu->root_pt);
    uint64_t *pt = page_phys_to_virt(mmu->root_pt);

    for (size_t n = 256; n < 512; n++) {
        if (pt[n] != kpt[n]) {
            pt[n] = kpt[n];
            // (Unnecessary if only A/D bits were changed.)
            flush_tlb_all();
        }
    }
}

// This needs to be called for every mmu whenever the root page table of the
// kernel mmu is changed.
static void sync_all_with_kernel_mmu(void)
{
    for (struct mmu *a = all_mmus.head; a; a = a->all_mmus.next)
        sync_with_kernel_mmu(a);
}

struct mmu *mmu_alloc(void)
{
    struct mmu *mmu = slob_allocz(&mmu_slob);
    if (!mmu)
        return NULL;

    mmu->root_pt = page_alloc_phy(1, PAGE_USAGE_PT);
    if (mmu->root_pt == INVALID_PHY_ADDR) {
        slob_free(&mmu_slob, mmu);
        return NULL;
    }

    if (kernel_mmu) {
        sync_with_kernel_mmu(mmu);
    } else {
        // Set all entries to unmapped.
        uint64_t *pt = page_phys_to_virt(mmu->root_pt);
        memset(pt, 0, PAGE_SIZE);
    }

    LL_APPEND(&all_mmus, mmu, all_mmus);

    return mmu;
}

void mmu_init(void)
{
    kernel_mmu = mmu_alloc();
    if (!kernel_mmu)
        panic("Could not allocate root page table.\n");

    kernel_mmu->is_kernel = true;
}

struct mmu *mmu_get_kernel(void)
{
    assert(kernel_mmu);
    return kernel_mmu;
}

// Write a leaf page table entry. Tries to allocate required page tables if they
// are not present yet, and the pte V bit is set.
//  alloc_pt_only: if set, don't actually write the pte; only allocate all the
//                 page table levels
//  returns: false iff a page table could not be allocated
static bool write_pt(struct mmu *mmu, uintptr_t virt, uint64_t pte,
                     bool alloc_pt_only)
{
    uint64_t pt_phy = mmu->root_pt;

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

            if (n == 0 && mmu == kernel_mmu)
                sync_all_with_kernel_mmu();
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

    flush_tlb_all();

    return true;
}

// Return raw PTE. Also returns the raw value of disabled PTEs (V flag not set),
// but only for entries on the last level.
static uint64_t read_pt(struct mmu *mmu, uintptr_t virt)
{
    uint64_t pt_phy = mmu->root_pt;

    for (size_t n = 0; n < MMU_NUM_LEVELS; n++) {
        size_t entry = MMU_PTE_INDEX(virt, n);
        uint64_t *pt = page_phys_to_virt(pt_phy);
        assert(pt);

        // Next page table entry.
        uint64_t npte = pt[entry];

        if (n == MMU_NUM_LEVELS -  1)
            return npte;

        if (!(npte & MMU_FLAG_V))
            return 0;

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

    assert(0);
}

// Internal; users use mmu_map() to unmap.
static void mmu_unmap(struct mmu* mmu, void *virt)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(!(ivirt & (PAGE_SIZE - 1)));

    uint64_t pte = read_pt(mmu, ivirt);

    if (pte & MMU_FLAG_V) {
        uint64_t phys = PTE_GET_PHYS(pte);

        struct phys_page *page = phys_page_get(phys);
        if (page && page->usage == PAGE_USAGE_USER && page->u.user.pte_list) {
            // This mapping _could_ be part of the list, but not necessarily.
            // If it's in there, it must be removed.
            struct mmu_pte_link **pe = &page->u.user.pte_list;
            while (*pe) {
                struct mmu_pte_link *link = *pe;
                if (link->mmu == mmu && link->map_addr == virt) {
                    *pe = link->next;
                    slob_free(&pte_link_slob, link);
                    break;
                }
                pe = &(*pe)->next;
            }
        }

        write_pt(mmu, ivirt, 0, false);
    }
}

static bool check_api_flags(int flags)
{
    int ok_flags = MMU_FLAG_R |
                   MMU_FLAG_W |
                   MMU_FLAG_X |
                   MMU_FLAG_G |
                   MMU_FLAG_A |
                   MMU_FLAG_D |
                   MMU_FLAG_RMAP;

    return (flags & ok_flags) == flags;
}

// Not all permission bit combinations are allowed. Return a valid combination
// by fudging the permissions.
static int fix_flags(int flags)
{
    // Promote write-only to read/write, as write-only is "reserved".
    if (flags & MMU_FLAG_W)
        flags |= MMU_FLAG_R;

    return flags;
}

// Note: may allow superpages at a later point
static bool check_region(void *addr, size_t size, bool kernel)
{
    uintptr_t ivirt = (uintptr_t)addr;

    if ((ivirt & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
        return false; // alignment

    // Must not cross boundaries (including user/kernel split)
    uint64_t min = kernel ? KERNEL_SPACE_BASE : 0;
    uint64_t max = kernel ? UINT64_MAX : MMU_ADDRESS_LOWER_MAX;
    if (ivirt < min)
        return false;
    if (max - ivirt < size - 1)
        return false;

    return true;
}

bool mmu_is_valid_user_region(void *addr, size_t size)
{
    return check_region(addr, size, false);
}

static bool validate_vaddr(struct mmu *mmu, uintptr_t ivirt, size_t size,
                           int flags)
{
    if (size != PAGE_SIZE)
        return false; // for now support only leaf pages

    if (!check_region((void *)ivirt, size, mmu->is_kernel))
        return false;

    // Global pages make sense for the kernel only. (Special cases, such as L4
    // style kernel info pages, must be excluded explicitly.)
    if (!mmu->is_kernel && (flags & MMU_FLAG_G))
        return false;

    return true;
}

bool mmu_map(struct mmu* mmu, void *virt, uint64_t phys, size_t size, int flags)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(check_api_flags(flags));
    flags = fix_flags(flags);

    if (!validate_vaddr(mmu, ivirt, size, flags))
        return false;

    uint64_t pte = 0;

    // MMU_FLAG_RMAP
    struct phys_page *page = NULL;
    struct mmu_pte_link *link = NULL;

    if (phys != INVALID_PHY_ADDR) {
        if (phys & (PAGE_SIZE - 1))
            return false; // alignment

        // Make sure the actual write_pt() succeeds. This is less of a pain
        // for later error handling.
        if (!write_pt(mmu, ivirt, pte, true))
            return false;

        pte |= flags & ~(uint64_t)MMU_FLAG_RMAP;
        pte |= MMU_FLAG_V;
        if (ivirt < KERNEL_SPACE_BASE)
            pte |= MMU_FLAG_U;
        pte |= PTE_FROM_PHYS(phys);

        if (flags & MMU_FLAG_RMAP) {
            page = phys_page_get(phys);
            if (!page || page->usage != PAGE_USAGE_USER)
                return false;

            link = slob_allocz(&pte_link_slob);
            if (!link)
                return false;
        }
    }

    // Unmap old entry, if any.
    mmu_unmap(mmu, virt);

    bool r = write_pt(mmu, ivirt, pte, false);
    assert(r); // must have been guaranteed due to page table pre-alloc.

    if (link) {
        *link = (struct mmu_pte_link){
            .mmu = mmu,
            .map_addr = virt,
            .next = page->u.user.pte_list,
        };
        page->u.user.pte_list = link;
    }

    return true;
}

bool mmu_protect(struct mmu* mmu, void *virt, int remove_flags, int add_flags)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(check_api_flags(add_flags));
    assert(check_api_flags(remove_flags));

    add_flags = fix_flags(add_flags);

    if ((add_flags | remove_flags) & MMU_FLAG_RMAP)
        return false;

    // (if superpages are ever added, we'll need this early to query their size)
    uint64_t pte = read_pt(mmu, ivirt);

    if (!validate_vaddr(mmu, ivirt, PAGE_SIZE, add_flags))
        return false;

    if (!(pte & MMU_FLAG_V))
        return !add_flags; // ok if no flags to add

    pte = (pte & ~(uint64_t)remove_flags) | add_flags;

    bool r = write_pt(mmu, ivirt, pte, false);
    assert(r); // can't fail, no page tables could have been missing/allocated

    return true;
}

void mmu_rmap_mark_ro(uint64_t phys)
{
    struct phys_page *page = phys_page_get(phys);

    if (page && page->usage == PAGE_USAGE_USER) {
        struct mmu_pte_link *link = page->u.user.pte_list;
        while (link) {
            bool r = mmu_protect(link->mmu, link->map_addr, MMU_FLAG_W, 0);
            assert(r); // shouldn't fail
            link = link->next;
        }
    }
}

// Similar to mmu_rmap_mark_ro(), but remove the mapping completely, instead of
// merely changing permission flags.
void mmu_rmap_unmap(uint64_t phys)
{
    struct phys_page *page = phys_page_get(phys);

    if (page && page->usage == PAGE_USAGE_USER) {
        while (1) {
            struct mmu_pte_link *link = page->u.user.pte_list;
            if (!link)
                break;
            // This also removes the entry.
            mmu_unmap(link->mmu, link->map_addr);
        }
    }
}

void mmu_switch_to(struct mmu* mmu)
{
    // Mode 9 = Sv48.
    uint64_t satp = (9ULL << 60) | PPN_FROM_PHYS(mmu->root_pt);
    asm volatile("csrw satp, %0" : : "r" (satp) : "memory");
    flush_tlb_all();
}
