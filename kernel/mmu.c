#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "slob.h"
#include "thread.h"

enum {
    // Following RISC-V
    MMU_FLAG_V = (1 << 0),
    MMU_FLAG_U = (1 << 4),
    MMU_FLAG_G = (1 << 5),

    // Mask for actual RISC-V flags.
    MMU_RISCV_FLAGS = (1 << 8) - 1,
};

struct mmu {
    bool is_kernel;
    uint64_t root_pt;

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

// Physical page number.
#define PPN_FROM_PHYS(phys) ((phys) >> PAGE_SHIFT)

// Given a valid PTE, return the full physical address in it.
#define PTE_GET_PHYS(pte) (((pte) >> 10) << PAGE_SHIFT)

// Given an aligned physical address, return the address shifted into the
// position as required by PTEs.
#define PTE_FROM_PHYS(phys) (PPN_FROM_PHYS(phys) << 10)

// Must be top-level PTE aligned.
static_assert(KERNEL_PS_BASE % MMU_PAGE_SIZE(0) == 0, "");
static_assert(KERNEL_PS_SIZE % MMU_PAGE_SIZE(0) == 0, "");

#define PS_PTE0_START MMU_PTE_INDEX(KERNEL_PS_BASE, 0)
#define PS_PTE0_END   MMU_PTE_INDEX(KERNEL_PS_BASE + KERNEL_PS_SIZE, 0)

static_assert(PS_PTE0_START < PS_PTE0_END, "");

// Whether the top-level PTE is for the global ("kernel") address space and thus
// need to be synced with kernel_mmu.
#define IS_KERNEL_PTE0(n) ((n) >= MMU_PTE_INDEX(KERNEL_SPACE_BASE, 0) && \
                           ((n) < PS_PTE0_START || (n) >= PS_PTE0_END))

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

struct mmu *mmu_get_kernel(void)
{
    assert(kernel_mmu);
    return kernel_mmu;
}

static void sync_with_kernel_mmu(struct mmu *mmu)
{
    if (mmu == kernel_mmu)
        return;

    uint64_t *kpt = page_phys_to_virt(kernel_mmu->root_pt);
    uint64_t *pt = page_phys_to_virt(mmu->root_pt);

    for (size_t n = 0; n < MMU_NUM_PTE_ENTRIES; n++) {
        if (IS_KERNEL_PTE0(n) && pt[n] != kpt[n]) {
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
// but only for entries on the wanted level.
//  level: level to read out PTE; MMU_LEAF_LEVEL for normal mappings
static uint64_t read_pt(struct mmu *mmu, uintptr_t virt, size_t level)
{
    assert(level < MMU_NUM_LEVELS);

    uint64_t pt_phy = mmu->root_pt;

    for (size_t n = 0; ; n++) {
        size_t entry = MMU_PTE_INDEX(virt, n);
        uint64_t *pt = page_phys_to_virt(pt_phy);
        assert(pt);

        // Next page table entry.
        uint64_t npte = pt[entry];

        if (n == level)
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

static void mmu_unmap_internal(struct mmu *mmu, void *virt, size_t page_size)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(page_size == 0 || page_size == PAGE_SIZE); // no superpages
    assert(!(ivirt & (PAGE_SIZE - 1)));

    uint64_t pte = read_pt(mmu, ivirt, MMU_LEAF_LEVEL);

    if (pte & MMU_FLAG_V) {
        uint64_t phys = PTE_GET_PHYS(pte);

        struct phys_page *page = phys_page_get(phys);
        if (page && page->usage == PAGE_USAGE_USER && page->u.user.pte_list) {
            // There might be Futex waiters on this virtual/physical memory page.
            // Don't care much about waking the exact waiter and just get rid of
            // them all, since this is a pretty obscure situation anyway. It is
            // required to do so for example to make threads re-enqueue them to
            // the correct page on COW.
            futex_wake(page, -1, INT64_MAX);

            // This mapping _could_ be part of the list, but not necessarily.
            // If it's in there, it must be removed. If it's not in there, it
            // was not mapped with MMU_FLAG_RMAP.
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
                   MMU_FLAG_A |
                   MMU_FLAG_D |
                   MMU_FLAG_RMAP |
                   MMU_FLAG_PS |
                   MMU_FLAG_NEW;

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

static bool check_region(void *addr, size_t size, bool kernel, int flags)
{
    uintptr_t ivirt = (uintptr_t)addr;

    if ((ivirt & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
        return false; // alignment

    if (!size)
        return false;

    if (flags & MMU_FLAG_PS) {
        // Must lie within PS region.
        if (kernel)
            return false;
        if (ivirt < KERNEL_PS_BASE || ivirt >= KERNEL_PS_END)
            return false;
        if (size > KERNEL_PS_SIZE - (ivirt - KERNEL_PS_BASE))
            return false;
    } else {
        // Must not cross boundaries (including user/kernel split)
        uint64_t min = kernel ? KERNEL_SPACE_BASE : 0;
        uint64_t max = kernel ? UINT64_MAX : MMU_ADDRESS_LOWER_MAX;
        if (ivirt < min)
            return false;
        if (max - ivirt < size - 1)
            return false;
        // And outside of PS region.
        uintptr_t end = ivirt + (size - 1); // inclusive
        if ((KERNEL_PS_BASE >= ivirt && KERNEL_PS_BASE <= end) ||
            (KERNEL_PS_END > ivirt && KERNEL_PS_END - 1 <= end))
            return false;
    }

    return true;
}

bool mmu_is_valid_user_region(void *addr, size_t size)
{
    return check_region(addr, size, false, 0);
}

static bool validate_vaddr(struct mmu *mmu, uintptr_t ivirt, size_t size,
                           int flags)
{
    if (size != PAGE_SIZE)
        return false; // for now support only leaf pages

    if (!check_region((void *)ivirt, size, mmu->is_kernel, flags))
        return false;

    // Global pages make sense for the kernel only. (Special cases, such as L4
    // style kernel info pages (if he had them), must be excluded explicitly.)
    if (!mmu->is_kernel && (flags & MMU_FLAG_G))
        return false;

    return true;
}

bool mmu_unmap(struct mmu *mmu, void *virt, size_t page_size, int flags)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(!(flags & ~(unsigned)(MMU_FLAG_PS)));

    if (!validate_vaddr(mmu, ivirt, page_size, flags))
        return false;

    mmu_unmap_internal(mmu, virt, page_size);
    return true;
}

bool mmu_map(struct mmu *mmu, void *virt, uint64_t phys, size_t size, int flags)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(check_api_flags(flags));
    flags = fix_flags(flags);

    assert(phys != INVALID_PHY_ADDR);

    if (mmu->is_kernel)
        flags |= MMU_FLAG_G;

    if (!validate_vaddr(mmu, ivirt, size, flags))
        return false;

    if ((flags & MMU_FLAG_NEW) &&
        (read_pt(mmu, ivirt, MMU_LEAF_LEVEL) & MMU_FLAG_V))
        return false;

    if (!(flags & (MMU_FLAG_R | MMU_FLAG_W | MMU_FLAG_X)))
        return false; // can't be represented

    if (phys & (PAGE_SIZE - 1))
        return false; // alignment

    // Make sure the actual write_pt() succeeds. This is less of a pain
    // for later error handling.
    if (!write_pt(mmu, ivirt, 0, true))
        return false;

    uint64_t pte = 0;
    pte |= flags & MMU_RISCV_FLAGS;
    pte |= MMU_FLAG_V;
    if (ivirt < KERNEL_SPACE_BASE)
        pte |= MMU_FLAG_U;
    pte |= PTE_FROM_PHYS(phys);

    struct phys_page *page = NULL;
    struct mmu_pte_link *link = NULL;
    if (flags & MMU_FLAG_RMAP) {
        page = phys_page_get(phys);
        if (!page || page->usage != PAGE_USAGE_USER)
            return false;

        link = slob_allocz(&pte_link_slob);
        if (!link)
            return false;
    }

    // Unmap old entry, if any.
    mmu_unmap_internal(mmu, virt, 0);

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

bool mmu_protect(struct mmu *mmu, void *virt, int remove_flags, int add_flags)
{
    uintptr_t ivirt = (uintptr_t)virt;

    assert(check_api_flags(add_flags));
    assert(check_api_flags(remove_flags));

    add_flags = fix_flags(add_flags);

    if ((add_flags | remove_flags) & MMU_FLAG_RMAP)
        return false;

    // (if superpages are ever added, we'll need this early to query their size)
    uint64_t pte = read_pt(mmu, ivirt, MMU_LEAF_LEVEL);

    if (!validate_vaddr(mmu, ivirt, PAGE_SIZE, add_flags))
        return false;

    if (!(pte & MMU_FLAG_V))
        return !add_flags; // ok if no flags to add

    pte = (pte & ~(uint64_t)remove_flags) | add_flags;

    bool r = write_pt(mmu, ivirt, pte, false);
    assert(r); // can't fail, no page tables could have been missing/allocated

    return true;
}

bool mmu_read_entry(struct mmu *mmu, void *virt, uint64_t *phys_out,
                    size_t *size_out, int *flags_out)
{
    *phys_out = INVALID_PHY_ADDR;
    *size_out = PAGE_SIZE;
    *flags_out = 0;

    uintptr_t ivirt = (uintptr_t)virt;
    int flags = 0;

    if (ivirt >= KERNEL_PS_BASE && ivirt < KERNEL_PS_END)
        flags |= MMU_FLAG_PS;

    if (!validate_vaddr(mmu, ivirt, PAGE_SIZE, flags))
        return false;

        // (if superpages are ever added, we'll need this early to query their size)
    uint64_t pte = read_pt(mmu, ivirt, MMU_LEAF_LEVEL);

    if (pte & MMU_FLAG_V) {
        *phys_out = PTE_GET_PHYS(pte);
        *flags_out = pte & ((1 << 8) - 1);
    }

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
            mmu_unmap_internal(link->mmu, link->map_addr, 0);
        }
    }
}

void mmu_switch_to(struct mmu *mmu)
{
    // Mode 9 = Sv48.
    uint64_t satp = (9ULL << 60) | PPN_FROM_PHYS(mmu->root_pt);
    asm volatile("csrw satp, %0" : : "r" (satp) : "memory");
    flush_tlb_all();
}

void mmu_assert_current(struct mmu *mmu, const char *file, int line, bool inv)
{
    uint64_t satp_reg;
    asm volatile("csrr %0, satp" : "=r" (satp_reg));
    uint64_t satp = (9ULL << 60) | PPN_FROM_PHYS(mmu->root_pt);
    if ((satp != satp_reg) ^ inv) {
        __assert_fail(inv ? "csr.satp != mmu.satp" : "csr.satp == mmu.satp",
                      file, line, "?");
    }
}

// Returns whether all sub-entries were free'd.
// (virt is not really needed and is used for debug output only; likewise
// free_root is only needed for debugging)
static bool free_pt_sub(struct mmu *mmu, size_t level, uint64_t *pt,
                        uintptr_t virt, bool free_root)
{
    bool all_unused = true;

    for (size_t n = 0; n < MMU_NUM_PTE_ENTRIES; n++) {
        // Shared kernel page table entries.
        if (level == 0 && !mmu->is_kernel && IS_KERNEL_PTE0(n))
            continue;

        uint64_t pte = pt[n];
        if (pte & MMU_FLAG_V) {
            uintptr_t virt_e = virt + MMU_PAGE_SIZE(level) * n;

            if (level == MMU_LEAF_LEVEL) {
                all_unused = false;
                if (free_root)
                    panic("Still mapped at virt=%p.\n", (void *)virt_e);
            } else {
                if (pte & (MMU_FLAG_R | MMU_FLAG_W | MMU_FLAG_X))
                    panic("unexpected superpage found");

                uint64_t sub_pt_phys = PTE_GET_PHYS(pte);
                uint64_t *sub_pt = page_phys_to_virt(sub_pt_phys);
                assert(sub_pt);

                if (free_pt_sub(mmu, level + 1, sub_pt, virt_e, free_root)) {
                    pt[n] = 0;

                    // (before we make it invalid)
                    if (level == 0 && mmu->is_kernel)
                        sync_all_with_kernel_mmu();

                    printf("free pt %zd:%lx at %p\n",
                           level, (long)sub_pt_phys, (void *)virt_e);
                    page_free_phy(sub_pt_phys, 1);
                } else {
                    all_unused = false;
                }
            }
        }
    }

    return all_unused;
}

// Free all page tables referenced by the address on a given level. virt selects
// page table entry on the give level, under which all page tables must be
// recursively freed. virt must be always aligned accordingly.
// If there are still leaf PTEs with V flags set, this blows up.
// level==MMU_LEAF_LEVEL operates on the last page table, and only checks
// whether the entries are deallocated correctly.
//  p_pte: pointer to the parent PTE (pointing to this page table), or if
//         level==0, NULL.
static void free_unused_pts(struct mmu *mmu, bool free_root)
{
    void *pt = page_phys_to_virt(mmu->root_pt);

    if (free_pt_sub(mmu, 0, pt, 0, free_root) && free_root) {
        page_free_phy(mmu->root_pt, 1);
        mmu->root_pt = INVALID_PHY_ADDR;
    }
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

void mmu_free(struct mmu *mmu)
{
    if (!mmu)
        return;

    assert(mmu != kernel_mmu);

    // Can't free in-use mmu struct.
    mmu_assert_current(mmu, __FILE__, __LINE__, true);

    free_unused_pts(mmu, true);
    assert(mmu->root_pt == INVALID_PHY_ADDR);

    LL_REMOVE(&all_mmus, mmu, all_mmus);

    slob_free(&mmu_slob, mmu);
}

void mmu_init(void)
{
    kernel_mmu = mmu_alloc();
    if (!kernel_mmu)
        panic("Could not allocate root page table.\n");

    kernel_mmu->is_kernel = true;
}
