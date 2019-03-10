#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "slob.h"
#include "virtual_memory.h"

#define PERM_MASK (KERN_MAP_PERM_R | KERN_MAP_PERM_W | KERN_MAP_PERM_X)

enum {
    // Flags for phys_page.u_flags (PAGE_USAGE_USER)
    // Flags for phys_page.u.user.vm_flags
    VM_PHYS_PAGE_FLAG_LOCKED_ALL    = (1 << 0),
    VM_PHYS_PAGE_FLAG_LOCKED_RO     = (1 << 1),
};

// Reference to pages of RAM data. This is a region of data (which can be mapped
// by 0 to N vm_mapping structs). It can either be anonymous memory, or a cache
// for a vm_object. In some cases, it can be both (private mappings, for which
// existing pages are anonymous memory, and new pages are fetched from
// vm_object - silly, but needed for some POSIX semantics).
//
// Whether this is cache or anon. memory depends on the user.
// In UVM terms, this is the "upper layer".
struct vm_resident {
    size_t refcount;
    // Current set of present resident pages. Unsorted. Requires linear search.
    // Note: this is obviously very inefficient. It has to deal with large
    //       sparse regions, and it should have minimal space overhead per page,
    //       so this should probably use something complicated, like a tree with
    //       leaf nodes that cover non-sparse regions. Which is why we don't
    //       bother and do something dumb - since in theory it could be fixed
    //       with just a bit of effort.
    size_t num_pages;
    struct vm_resident_page *pages; // pages[0..num_pages-1]
};

struct vm_resident_page {
    // Byte offset of the page into the object. (Always page aligned.)
    uint64_t offset;
    // The address of a valid physical page allocated as PAGE_USAGE_USER. It
    // contributes to phys_page.u.user.vm_refcount. (If that refcount goes to 0,
    // no vm_resident objects reference it, and it is deallocated.)
    // The page can also be not of type PAGE_USAGE_USER. Then COW is not
    // supported.
    uint64_t phys_addr;
};

// In UNIX terms, this could be a kernel internal "file" (including associated
// block cache pages). For example, in UNIX terms, this would represent the
// kernel memory structure for a file on disk, which can be opened multiple
// times (and have independent FDs). vm_object_ref is closer to an opened FD.
//
// In UVM terms, this is the "lower layer".
struct vm_object {
    // Multiple vm_object_ref can reference a vm_object.
    size_t refcount;

    uint64_t size;

    // Special behavior for fork().
    bool is_anonymous;

    // Actual backend. This is essentially the page fault handler.
    const struct vm_object_ops *ops;
    void *ops_ud;

    // Cached/dirty RAM pages.
    struct vm_resident *resident;
};

// A view on a vm_object. This is different from vm_object so that some POSIX
// non-sense like MAP_PRIVATE is possible. Also, you may want to restrict access
// to the memory or provide otherweise different behavior. For the most part,
// duplicate vm_object_refs will look like they still refer to the same thing,
// just that some metadata changes don't propagate.
//
// For our kernel, userspace-visible handles will refer to this.
//
// On a page fault, this will first try to see whether the page exist in
// vm_object_ref.resident, and if not, get vm_object to fetch/allocate the page.
struct vm_object_ref {
    // Userspace will probably be able to reference the same vm_object_ref via
    // multiple FDs or handles.
    size_t refcount;

    // This provides the backing storage for the memory. The resident object
    // acts as a cache for it. There are 2 cases:
    //  a) vm_object_ref.resident == vm_object_ref.object.resident
    //     => Like a normal mmap()'d region.
    //  b) vm_object_ref.resident != vm_object_ref.object.resident
    //     => Like a mmap()'d file with MAP_PRIVATE.
    // Anonymous memory uses a dummy vm_object and always keeps data in the
    // vm_object.resident field (i.e. case a)).
    // Anonymous memory after fork() just creates a new vm_object (with
    // phys_pages that have a refcount>1, so that they will COW).
    // Revoked refs have this set to NULL.
    struct vm_object *object;

    // Data of this object present in memory. Note that, like object->resident,
    // all offsets are relative to the start of the vm_object, not the
    // vm_object_ref.
    // vm_object_ref always accesses this for data, never object->resident. The
    // only exception is when a page is not resident; then (in case b)),
    // object->resident may have the page that is missing.
    // Revoked refs have this set to NULL.
    struct vm_resident *resident;

    // Range of the accesses data with start (a) and end (b) byte offsets. All
    // accesses are relative to offset_a, and are "sliced off" at offset_b.
    // offset_a+offset_b can be larger then the vm_object size. offset_b can be
    // set to UINT64_MAX for full access.
    // Note that vm_object_ref.resident also uses "full" offsets.
    uint64_t offset_a, offset_b;

    // PERM_MASK bits for allowed access.
    int flags;
};

// Represents a region mapped into a virtual address space. It references some
// kind of backing storage.
struct vm_mapping {
    // Reserved address region for this mapping. Mappings of size 0 are not
    // allowed. The last page of the address space can't be used, but then
    // again it already ends at (MMU_ADDRESS_LOWER_MAX+1).
    uintptr_t virt_start;
    uintptr_t virt_end;

    // Offset into data. (Is added on top of data.offset.)
    uint64_t offset;

    // If true, this is a special type of map that is managed by other parts of
    // the kernel, and which the VM system never synchronizes with struct mmu.
    bool kernel_reserved;

    // mmap() flags, including effective permission flags.
    int flags;

    // vm_aspace.mappings list
    struct {
        struct vm_mapping *prev, *next;
    } mappings;

    // Backing store with all the metadata. This is always specific to a
    // mapping, and sharing them does not make sense, because most mappings will
    // have varying sizes and offsets, even if they refer to the same memory, so
    // this is not a pointer.
    struct vm_object_ref data;
};

struct vm_aspace {
    struct mmu *mmu;

    // List of all mappings in this address space. Sorted by address. This
    // should probably be accompanied with a data structure for faster lookup,
    // as every page fault goes though this. Adding this is no problem in
    // theory, and thus us is left as future exercise.
    struct {
        struct vm_mapping *head, *tail;
    } mappings;

    struct vm_aspace_owners owners;
};

static void vm_objref_destroy(struct vm_object_ref *ref);
static void vm_object_unref(struct vm_object *obj);

static struct slob slob_vm_aspace = SLOB_INITIALIZER(struct vm_aspace);
static struct slob slob_vm_mapping = SLOB_INITIALIZER(struct vm_mapping);
static struct slob slob_vm_resident = SLOB_INITIALIZER(struct vm_resident);
static struct slob slob_vm_object = SLOB_INITIALIZER(struct vm_object);
static struct slob slob_vm_object_ref = SLOB_INITIALIZER(struct vm_object_ref);

static struct vm_object_ops anon_mem_ops = {0};

static struct phys_page *vm_resident_get_phys_page(struct vm_resident_page *page)
{
    struct phys_page *phys_page = phys_page_get(page->phys_addr);

    // It makes no sense for this to fail as long as they're correctly
    // allocated.
    assert(phys_page);
    assert(phys_page->usage == PAGE_USAGE_USER);
    assert(phys_page->u.user.vm_refcount > 0);

    return phys_page;
}

// Warning: you must remove the entry from vm_resident.pages[] containing this.
//          Otherwise you get a dangling physical memory pointer.
static void vm_resident_destroy_page(struct vm_resident_page *page)
{
    struct phys_page *phys_page = vm_resident_get_phys_page(page);

    // Unmap it completely. Unfortunately, this also unmaps PTEs that
    // can still legitimately access it (at least if vm_refcount>1),
    // but we have no control over this. The PTEs can be reestablished
    // on demand (via page faults).
    // TODO: this will happen to all pages in a parent process every
    //       time a child terminates. Maybe keep a list of all
    //       vm_mappings that use a vm_resident? A vm_mapping can use
    //       up to 2 vm_residents, though.
    mmu_rmap_unmap(page->phys_addr);
    phys_page->u.user.vm_refcount -= 1;

    if (phys_page->u.user.vm_refcount == 0)
        page_free_phy(page->phys_addr, 1);
}

static void vm_resident_unref(struct vm_resident *res)
{
    if (!res)
        return;

    assert(res->refcount > 0);
    res->refcount -= 1;

    if (res->refcount == 0) {
        for (size_t n = 0; n < res->num_pages; n++)
            vm_resident_destroy_page(&res->pages[n]);

        free(res->pages);
        slob_free(&slob_vm_resident, res);
    }
}

// Create a new vm_resident struct. If base!=NULL, then copy and create COW
// references to all pages present in base.
static struct vm_resident *vm_resident_mooh(struct vm_resident *base)
{
    struct vm_resident *new = slob_allocz(&slob_vm_resident);
    if (!new)
        return NULL;

    new->refcount = 1;

    if (base) {
        new->num_pages = base->num_pages;
        new->pages = malloc(sizeof(new->pages[0]) * new->num_pages);

        if (!new->pages) {
            slob_free(&slob_vm_resident, new);
            return NULL;
        }

        memcpy(new->pages, base->pages, sizeof(new->pages[0]) * new->num_pages);

        for (size_t n = 0; n < new->num_pages; n++) {
            struct vm_resident_page *src = &new->pages[n];
            struct phys_page *phys_page = vm_resident_get_phys_page(src);

            // Revoke write access for all VM mappings of this page. Write
            // accesses will cause a page fault, which copy the memory, or
            // just reenable write access if the refcount is 1 again.
            mmu_rmap_mark_ro(src->phys_addr);
            phys_page->u.user.vm_refcount += 1;
        }
    }

    return new;
}

// Return the page at the given offset, or NULL if not present.
static struct vm_resident_page *vm_resident_get_page(struct vm_resident *res,
                                                     uint64_t offset)
{
    // Dumb linear search. See vm_resident.num_pages for a comment on this.
    for (size_t n = 0; n < res->num_pages; n++) {
        struct vm_resident_page *page = &res->pages[n];
        if (page->offset == offset)
            return page;
    }
    return NULL;
}

// Make sure the given page referenced is writable. Returns false on OOM.
static bool vm_resident_make_writable(struct vm_resident_page *page)
{
    struct phys_page *phys_page = vm_resident_get_phys_page(page);

    // Replace with an actual copy if needed.
    if (phys_page->u.user.vm_refcount > 1) {
        // There may be other processes which may need to unmap the address in
        // page->phys_addr - otherwise they'll continue to read the old page.
        // This would result in them seeing outdated data.
        mmu_rmap_unmap(page->phys_addr);

        uint64_t phys = page_alloc_phy(1, PAGE_USAGE_USER);
        if (phys == INVALID_PHY_ADDR)
            return false; // OOM

        struct phys_page *phys_page_new = phys_page_get(phys);

        assert(phys_page_new);
        assert(phys_page_new->usage == PAGE_USAGE_USER);
        assert(phys_page_new->u.user.vm_refcount == 0);

        void *src = page_phys_to_virt(page->phys_addr);
        void *dst = page_phys_to_virt(phys);

        assert(src);
        assert(dst);

        memcpy(dst, src, PAGE_SIZE);

        page->phys_addr = phys;
        phys_page_new->u.user.vm_refcount += 1;
        phys_page->u.user.vm_refcount -= 1;
    }

    return true;
}

static bool vm_resident_is_writable(struct vm_resident_page *page)
{
    struct phys_page *phys_page = vm_resident_get_phys_page(page);
    return phys_page->u.user.vm_refcount == 1;
}

// Increase capacity of res->pages[] so that 1 new entry can be added.
// Returns false on failure.
static bool vm_resident_reserve_entry(struct vm_resident *res)
{
    if (res->num_pages == (size_t)-1)
        return false;

    struct vm_resident_page *new_pages =
        realloc(res->pages, sizeof(res->pages[0]) * (res->num_pages + 1));
    if (!new_pages)
        return false; // OOM
    res->pages = new_pages;
    return true;
}

// Allocate a new page and add it to the page list. Entry must not have existed
// yet.
// (Note: a real system would possibly prune caches on low memory, make it
//  possible to customize handling OOM, and so on. We don't yet, so this cannot
//  block or sleep.)
static struct vm_resident_page *vm_resident_alloc_page(struct vm_resident *res,
                                                       uint64_t offset)
{
    assert(!vm_resident_get_page(res, offset));

    if (!vm_resident_reserve_entry(res))
        return NULL;

    uint64_t phys = page_alloc_phy(1, PAGE_USAGE_USER);
    if (phys == INVALID_PHY_ADDR)
        return NULL; // OOM

    struct phys_page *phys_page = phys_page_get(phys);

    assert(phys_page);
    assert(phys_page->usage == PAGE_USAGE_USER);
    assert(phys_page->u.user.vm_refcount == 0);

    phys_page->u.user.vm_refcount = 1;

    void *virt = page_phys_to_virt(phys);
    assert(virt);
    memset(virt, 0, PAGE_SIZE);

    struct vm_resident_page *new = &res->pages[res->num_pages++];
    *new = (struct vm_resident_page){
        .offset = offset,
        .phys_addr = phys,
    };

    return new;
}

// Add some other page to this struct. This setups the page for COW. Entry must
// not have existed yet.
static struct vm_resident_page *vm_resident_share_page(
    struct vm_resident *res, uint64_t offset, struct vm_resident_page *other)
{
    assert(!vm_resident_get_page(res, offset));

    if (!vm_resident_reserve_entry(res))
        return NULL;

    struct phys_page *phys_page = vm_resident_get_phys_page(other);

    phys_page->u.user.vm_refcount += 1;

    struct vm_resident_page *new = &res->pages[res->num_pages++];
    *new = (struct vm_resident_page){
        .offset = offset,
        .phys_addr = other->phys_addr,
    };

    return new;
}

// Notify the vm_resident that pages below a and above b need to be removed.
static void vm_resident_slice(struct vm_resident *res, size_t a, size_t b)
{
    for (size_t n = res->num_pages; n > 0; n--) {
        struct vm_resident_page *page = &res->pages[n - 1];
        if (page->offset < a || page->offset >= b) {
            vm_resident_destroy_page(page);

            res->pages[n - 1] = res->pages[res->num_pages - 1];
            res->num_pages -= 1;
        }
    }

    // TODO: maybe resize pages[] array if enough pages were removed
}

static void vm_aspace_dump(struct vm_aspace *as)
{
    printf("vm_aspace %p:\n", as);
    for (struct vm_mapping *m = as->mappings.head; m; m = m->mappings.next) {
        char perm[] = "--- --";
        if (m->flags & KERN_MAP_PERM_R)
            perm[0] = 'R';
        if (m->flags & KERN_MAP_PERM_W)
            perm[1] = 'W';
        if (m->flags & KERN_MAP_PERM_X)
            perm[2] = 'X';
        if (m->flags & KERN_MAP_FORK_COPY)
            perm[4] = 'C';
        if (m->flags & KERN_MAP_FORK_SHARE)
            perm[5] = 'S';
        printf("  %016lx - %016lx %s ", (long)m->virt_start,
               (long)m->virt_end, perm);
        if (m->data.object) {
            printf("%zu", m->data.resident->num_pages);
            if (m->data.object->resident != m->data.resident)
                printf("/%zu", m->data.object->resident->num_pages);
        } else {
            printf("DEAD");
        }
        printf("\n");
    }
}

struct vm_aspace *vm_aspace_create(void)
{
    struct vm_aspace *as = slob_allocz(&slob_vm_aspace);
    if (!as)
        return NULL;

    as->mmu = mmu_alloc();
    if (!as->mmu) {
        slob_free(&slob_vm_aspace, as);
        return NULL;
    }

    return as;
}

void vm_aspace_free(struct vm_aspace *as)
{
    if (!as)
        return;

    while (as->mappings.head) {
        struct vm_mapping *m = as->mappings.head;
        bool r = vm_munmap(as, (void *)m->virt_start, m->virt_end - m->virt_start);
        assert(r); // non-splitting unmap, always must succeed
    }

    mmu_free(as->mmu);
    slob_free(&slob_vm_aspace, as);
}

struct vm_aspace_owners *vm_aspace_get_owners(struct vm_aspace *as)
{
    return &as->owners;
}

struct mmu *vm_aspace_get_mmu(struct vm_aspace *as)
{
    return as->mmu;
}

// Return the vm_mapping at which the byte at addr falls into, or if there is
// no exact match, the next mapping after addr, or NULL if none.
static struct vm_mapping *vm_aspace_lookup(struct vm_aspace *as, void *addr)
{
    // Dumb linear search. See vm_aspace.mappings for a comment on this.
    for (struct vm_mapping *m = as->mappings.head; m; m = m->mappings.next) {
        if (m->virt_end > (uintptr_t)addr)
            return m;
    }
    return NULL;
}

// Create a copy of src. It's not inserted into the aspace list.
static struct vm_mapping *dup_mapping(struct vm_mapping *src)
{
    struct vm_mapping *new = slob_allocz(&slob_vm_mapping);
    if (!new)
        return NULL;

    *new = *src;
    new->mappings.next = new->mappings.prev = NULL;

    if (new->data.object)
        new->data.object->refcount += 1;

    if (new->data.resident)
        new->data.resident->refcount += 1;

    return new;
}

static void mapping_mmu_unmap_range(struct vm_aspace *as, struct vm_mapping *m,
                                    uintptr_t a, uintptr_t b)
{
    if (m->kernel_reserved)
        return;

    for (uintptr_t addr = a; addr < b; addr += PAGE_SIZE) {
        bool r = mmu_map(as->mmu, (void *)addr, INVALID_PHY_ADDR, PAGE_SIZE, 0);
        // unmapping can fail only on broken input, such as inconsistent user-
        // space boundaries or unaligned addresses
        assert(r);
    }
}

// Reduce the address range of the mapping. This must not reduce the total size
// to 0 or below. unmap_parts=true if this is an active mapping.
static void mapping_clamp(struct vm_aspace *as, struct vm_mapping *m,
                          bool unmap_parts, uintptr_t a, uintptr_t b)
{
    assert(!(a & (PAGE_SIZE - 1)));
    assert(!(b & (PAGE_SIZE - 1)));
    assert(a >= m->virt_start && a < m->virt_end);
    assert(b > m->virt_start && b <= m->virt_end);

    if (unmap_parts && a > m->virt_start)
        mapping_mmu_unmap_range(as, m, m->virt_start, a);
    if (unmap_parts && b < m->virt_end)
        mapping_mmu_unmap_range(as, m, b, m->virt_end);

    m->offset += a - m->virt_start;

    m->virt_start = a;
    m->virt_end = b;

    // TODO: would be nice to free unused resident pages if someone made an
    //       unused hole into a mmap() allocation. Would need to check for
    //       non-shared anonymous memory.
}

// (m must not be in as->mappings, or have entries in mmu yet)
static void mapping_destroy_only(struct vm_mapping *m)
{
    assert(m->data.refcount == 1);
    m->data.refcount = 0;
    vm_objref_destroy(&m->data);
    slob_free(&slob_vm_mapping, m);
}

// (m must be in as->mappings)
static void mapping_destroy_unlink(struct vm_aspace *as, struct vm_mapping *m)
{
    mapping_mmu_unmap_range(as, m, m->virt_start, m->virt_end);

    LL_REMOVE(&as->mappings, m, mappings);
    mapping_destroy_only(m);
}

// Some operations on an address range require splitting mappings that intersect
// with it (mmap, mprotect, munmap all can be applied to arbitrary ranges). This
// function splits the mappings that intersect with the boundary. It creates new
// mappings with the same properties, which then can be changed by the caller.
//  addr, length: range
//  unmap: don't actually insert new mappings within the range, and unmap
//         anything within the range
//  overwrite: fail if there are any collisions
//  out_a: set to first mapping within range (or NULL if none)
//  out_b: set to first mapping after range (or NULL if none)
//  returns: success (out_* are set to NULL on failure)
// Note: this also fails if any kernel reserved mappings are within the range.
static bool split_map(struct vm_aspace *as, void *addr, size_t length,
                      bool unmap, bool overwrite,
                      struct vm_mapping **out_a,
                      struct vm_mapping **out_b)
{
    *out_a = NULL;
    *out_b = NULL;

    if (!mmu_is_valid_user_region(addr, length) || !length)
        return false;

    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + length;

    vm_aspace_dump(as);

    struct vm_mapping *a = vm_aspace_lookup(as, addr);
    printf("%p -> %p\n", (void *)addr, a);
    if (!a || end <= a->virt_start)
        return true; // nothing was mapped at addr or after

    if (overwrite)
        return false;

    struct vm_mapping *b = a;
    for (struct vm_mapping *m = a; m; m = m->mappings.next) {
        if (m->virt_start >= end)
            break;
        b = m;

        if (m->kernel_reserved)
            return false; // can't change this
    }

    bool a_split = start > a->virt_start && start < a->virt_end;
    bool b_split = end > b->virt_start && end < b->virt_end;
    // A single region is split into 3 (or 2 on unmap).
    bool ab_split = a == b && a_split && b_split;

    printf("splitinser %p %p %d %d %d\n", a, b, a_split, b_split, ab_split);

    struct vm_mapping *inner_a = a;
    struct vm_mapping *inner_b = b->mappings.next;

    if (a_split) {
        if (!unmap || ab_split) {
            struct vm_mapping *a_new = dup_mapping(a);
            if (!a_new)
                return false;

            mapping_clamp(as, a_new, false, start, a->virt_end);
            LL_INSERT_AFTER(&as->mappings, a, a_new, mappings);
        }

        mapping_clamp(as, a, true, a->virt_start, start);
        inner_a = a->mappings.next;
    }

    if (b_split) {
        // (On ab_split, a_new is the new middle mapping.)
        if (!unmap && !ab_split) {
            struct vm_mapping *b_new = dup_mapping(b);
            if (!b_new)
                return false;

            mapping_clamp(as, b_new, false, b->virt_start, end);
            LL_INSERT_BEFORE(&as->mappings, b, b_new, mappings);
        }

        mapping_clamp(as, b, true, end, b->virt_end);
        inner_b = b;
    }

    if (unmap) {
        while (inner_a) {
            if (inner_a == inner_b)
                break;
            struct vm_mapping *next = inner_a->mappings.next;
            mapping_destroy_unlink(as, inner_a);
            inner_a = next;
        }
    } else {
        *out_a = inner_a;
        *out_b = inner_b;
    }

    return true;
}

bool vm_munmap(struct vm_aspace *as, void *addr, size_t length)
{
    struct vm_mapping *unused1, *unused2;
    return split_map(as, addr, length, true, false, &unused1, &unused2);
}

// new must be a fully setup vm_mapping that has not been added to a vm_aspace
// yet. This function adds it, and takes care of unmapping previous mappings
// that collide with it.
// On failure, new is destroyed.
//  overwrite: if true, allow implicitly unmapping
static bool vm_insert_mapping(struct vm_aspace *as, struct vm_mapping *new,
                              bool overwrite)
{
    struct vm_mapping *unused1, *unused2;
    printf("map %p - %p\n", (void*)new->virt_start, (void *)new->virt_end);
    if (!split_map(as, (void *)new->virt_start, new->virt_end - new->virt_start,
                   true, overwrite, &unused1, &unused2))
    {
        mapping_destroy_only(new);
        printf("fail\n");
        return false;
    }

    struct vm_mapping *m = vm_aspace_lookup(as, (void *)new->virt_start);
    LL_INSERT_BEFORE(&as->mappings, m, new, mappings);
    vm_aspace_dump(as);
    return true;
}

// Find a free region for the given size. Returns -1 on failure; also may
// return nonsense (verify result with mmu_is_valid_user_region()).
// Currently always tries to make sure unused page sized padding is present, to
// function as guard pages.
// Certainly could be cleverer, especially if regions are involved that need
// to grow. It shouldn't be O(n) either.
static void *find_region(struct vm_aspace *as, size_t length)
{
    uintptr_t start = 0x200000;
    size_t guard_size = PAGE_SIZE;
    length += guard_size * 2;

    struct vm_mapping *m = vm_aspace_lookup(as, (void *)start);
    while (m) {
        if (start + length <= m->virt_start)
            break;
        start = m->virt_end;
        m = m->mappings.next;
    }

    return (void *)(start + guard_size);
}

void *vm_mmap(struct vm_aspace *as, void *addr, size_t length, int flags,
              struct vm_object_ref *obj, uint64_t offset)
{
    struct vm_mapping *new = NULL;

    if ((flags & KERN_MAP_FORK_COPY) && (flags & KERN_MAP_FORK_SHARE))
        goto fail; // flag combination not allowed

    if (addr == (void *)-1) {
        flags = flags & ~(unsigned)KERN_MAP_OVERWRITE;
        addr = find_region(as, length);
    }

    if (!mmu_is_valid_user_region(addr, length) || !length)
        goto fail;

    new = slob_allocz(&slob_vm_mapping);
    if (!new)
        goto fail;

    new->virt_start = (uintptr_t)addr;
    new->virt_end = new->virt_start + length;
    new->flags = flags & (PERM_MASK | KERN_MAP_FORK_COPY | KERN_MAP_FORK_SHARE);

    struct vm_object_ref *ref = NULL;
    if (obj) {
        ref = vm_objref_dup(obj);
        ref->offset_a += offset; // TODO: or is this absolute
    } else {
        if (offset)
            goto fail; // invalid parameter
        ref = vm_objref_create_anon(length);
    }
    if (!ref)
        goto fail; // OOM

    // Inelegantly transplant the new ref into new->data.
    assert(ref->refcount == 1);
    new->data = *ref;
    slob_free(&slob_vm_object_ref, ref); // without any dtor

    int req_perms = flags & PERM_MASK;
    if ((req_perms & new->data.flags) != req_perms)
        goto fail; // insufficient R/W/X permissions

    if ((flags & KERN_MAP_COW) && new->data.object) {
        if (new->data.object->is_anonymous)
            goto fail; // flag combination not allowed (nonsense on fork())

        // If this was already a COW objref, then we obviously need to keep the
        // COW'd data. On the other hand, if data.resident merely points to the
        // object cache, it's wrong to COW these, as foreign writes to them
        // should still be visible.
        struct vm_resident *base = NULL;
        if (new->data.resident != new->data.object->resident)
            base = new->data.resident;

        // TODO: don't copy pages that are outside of mapping range and are
        //       never needed
        struct vm_resident *newres = vm_resident_mooh(base);
        if (!newres)
            goto fail; // OOM
        vm_resident_unref(new->data.resident);
        new->data.resident = newres;
    }

    if (vm_insert_mapping(as, new, flags & KERN_MAP_OVERWRITE))
        return addr;
    new = NULL;
    goto fail;

fail:
    if (new)
        mapping_destroy_only(new);
    return (void *)-1;
}

bool vm_reserve(struct vm_aspace *as, void *addr, size_t length)
{
    if (!length)
        return true;

    if (!mmu_is_valid_user_region(addr, length))
        return false;

    struct vm_mapping *new = slob_allocz(&slob_vm_mapping);
    if (!new)
        return NULL;

    new->virt_start = (uintptr_t)addr;
    new->virt_end = new->virt_start + length;

    new->kernel_reserved = true;

    return vm_insert_mapping(as, new, false);
}

static void vm_objref_destroy(struct vm_object_ref *ref)
{
    assert(ref->refcount == 0);

    if (ref->object)
        vm_object_unref(ref->object);
    if (ref->resident)
        vm_resident_unref(ref->resident);
}

void vm_objref_unref(struct vm_object_ref *ref)
{
    assert(ref->refcount > 0);
    ref->refcount -= 1;
    if (ref->refcount == 0)
        vm_objref_destroy(ref);
}

struct vm_object_ref *vm_objref_dup(struct vm_object_ref *ref)
{
    struct vm_object_ref *new = slob_allocz(&slob_vm_object_ref);
    if (!new)
        return NULL;

    *new = *ref;

    new->refcount = 1;
    if (new->object)
        new->object->refcount += 1;
    if (new->resident)
        new->resident->refcount += 1;

    return new;
}

// Ownership goes to callee, even on error, i.e. frees obj on error.
static struct vm_object_ref *objref_create_initial(struct vm_object *obj)
{
    if (!obj)
        return NULL;

    assert(obj->refcount == 1); // anything else doesn't make sense
    assert(obj->resident); // require properly constructed object

    struct vm_object_ref *ref = slob_allocz(&slob_vm_object_ref);
    if (!ref) {
        vm_object_unref(obj);
        return NULL;
    }

    ref->refcount = 1;
    ref->object = obj;
    ref->resident = obj->resident;

    // (vm_object is also an owner of resident)
    ref->resident->refcount += 1;

    ref->offset_a = 0;
    ref->offset_b = UINT64_MAX;
    ref->flags = KERN_MAP_PERM_R | KERN_MAP_PERM_W | KERN_MAP_PERM_X;

    return ref;
}

static void vm_object_unref(struct vm_object *obj)
{
    assert(obj->refcount > 0);
    obj->refcount -= 1;
    if (obj->refcount == 0) {
        if (obj->ops->free)
            obj->ops->free(obj->ops_ud);
        vm_resident_unref(obj->resident);
    }
}

// (base_res as a hack to provide a basic set of pre-existing pages)
static struct vm_object_ref *vm_objref_create_internal(
    const struct vm_object_ops *ops,  void *ud, struct vm_resident *base_res)
{
    struct vm_object *obj = slob_allocz(&slob_vm_object);
    if (!obj)
        return NULL;

    obj->refcount = 1;
    obj->is_anonymous = ops == &anon_mem_ops;
    obj->ops = ops;
    obj->ops_ud = ud;

    obj->resident = vm_resident_mooh(base_res);
    if (!obj->resident) {
        slob_free(&slob_vm_object, obj);
        return NULL;
    }

    return objref_create_initial(obj);
}

struct vm_object_ref *vm_objref_create(const struct vm_object_ops *ops, void *ud)
{
    return vm_objref_create_internal(ops, ud, NULL);
}

struct vm_object_ref *vm_objref_create_anon(uint64_t size)
{
    struct vm_object_ref *ref = vm_objref_create(&anon_mem_ops, NULL);
    if (ref)
        vm_objref_set_size(ref, size);
    return ref;
}

struct vm_object_ref *vm_objref_copy_anon(struct vm_object_ref *ref)
{
    if (!ref || !ref->object || !ref->object->is_anonymous)
        return NULL;

    // KERN_MAP_COW is not allowed on anonymous memory. Could
    // probably handle this by merging the two vm_resident, but
    // why bother - disallowing it is simpler.
    assert(ref->resident == ref->object->resident);

    struct vm_object_ref *new =
        vm_objref_create_internal(&anon_mem_ops, NULL, ref->resident);
    if (!new)
        return NULL;

    vm_objref_set_size(new, ref->object->size);

    return new;
}

bool vm_fork(struct vm_aspace *dst, struct vm_aspace *src)
{
    if (dst->mappings.head)
        return false;

    for (struct vm_mapping *m = src->mappings.head; m; m = m->mappings.next) {
        if (!(m->flags & (KERN_MAP_FORK_COPY | KERN_MAP_FORK_SHARE)))
            continue;

        int flags = m->flags;
        struct vm_object_ref *ref = &m->data;

        if (m->flags & KERN_MAP_FORK_COPY) {
            if (!m->data.object) {
                // Revoked reference. Can be mapped, but can't be  "unrevoked",
                // so leave it as it is.
            } else if (m->data.object->is_anonymous) {
                // Anonymous memory has the special property of using full copy
                // semantics.
                ref = vm_objref_copy_anon(ref);
                if (!ref)
                    goto fail;
            } else {
                flags |= KERN_MAP_COW;
            }
        }

        void *r = vm_mmap(dst, (void *)m->virt_start, m->virt_end - m->virt_start,
                          flags, ref, m->offset);

        if (ref != &m->data)
            vm_objref_unref(ref);

        if (KERN_MMAP_FAILED(r))
            goto fail; // probably OOM
    }

    return true;

fail:
    while (dst->mappings.head) {
        struct vm_mapping *m = dst->mappings.head;
        bool r = vm_munmap(dst, (void *)m->virt_start, m->virt_end - m->virt_start);
        assert(r); // non-splitting unmap, always must succeed
    }
    return false;
}

/*
int vm_objref_page_ctrl(struct vm_object_ref *ref, uint64_t offset, int flags)
{
}
*/

uint64_t vm_objref_page_create_phys(struct vm_object_ref *ref, uint64_t offset)
{
    if (!ref->object)
        return INVALID_PHY_ADDR;

    struct vm_resident_page *page = vm_resident_get_page(ref->resident, offset);
    if (!page)
        page = vm_resident_alloc_page(ref->resident, offset);

    return page ? page->phys_addr : INVALID_PHY_ADDR;
}

void vm_objref_set_size(struct vm_object_ref *ref, uint64_t size)
{
    if (!ref->object)
        return; // was revoked; ignore

    if (ref->object->size < size) {
        // Prune old pages. (Yes, this ignores pages created due to KERN_MAP_COW
        // in vm_object_refs. That's fine.)
        vm_resident_slice(ref->object->resident, 0, size);
    }

    ref->object->size = size;
}

bool vm_aspace_handle_page_fault(struct vm_aspace *as, void *addr, int access)
{
    // Exactly one R/W/X bit must be set.
    assert(access);
    assert((access & PERM_MASK) == access);
    assert(!(access & (access - 1)));

    uintptr_t iaddr = (uintptr_t)addr;
    iaddr = iaddr & ~(uintptr_t)(PAGE_SIZE - 1);

    const char *ftype = "?";
    switch (access) {
    case KERN_MAP_PERM_R: ftype = "read"; break;
    case KERN_MAP_PERM_W: ftype = "write"; break;
    case KERN_MAP_PERM_X: ftype = "exec"; break;
    }
    printf("fault %s at %lx\n", ftype, iaddr);
    vm_aspace_dump(as);

    struct vm_mapping *m = vm_aspace_lookup(as, addr);
    if (!m || iaddr < m->virt_start || iaddr >= m->virt_end || m->kernel_reserved)
        return false; // unknown/unmanaged memory region

    struct vm_object *object = m->data.object;
    struct vm_resident *resident = m->data.resident;

    if (!object)
        return false; // trying to access revoked object

    uintptr_t offset = iaddr - m->virt_start + m->offset + m->data.offset_a;
    if (offset >= m->data.offset_b)
        return false; // access to region without access

    if (offset >= object->size)
        return false; // out of bounds access

    if (!(access & m->flags))
        return false; // no permissions (e.g. write to R/O mapping)

    // Whether this mapping principally uses COW.
    bool use_priv = resident != object->resident;
    bool write = access & KERN_MAP_PERM_W;
    bool allow_write = m->flags & KERN_MAP_PERM_W;

    struct vm_resident_page *page_u = vm_resident_get_page(resident, offset);

    struct vm_resident_page *page_l = NULL;
    if (!page_u && use_priv)
        page_l = vm_resident_get_page(object->resident, offset);

    // Need to get a new page from the backing layer?
    if (!page_u && (!use_priv || !page_l)) {
        if (object->is_anonymous) {
            page_u = vm_resident_alloc_page(resident, offset);
            if (!page_u)
                return false; // OOM
        } else {
            if (!object->ops->read_page)
                return false; // whatever
            // This may block and generally change the state in an unknown way.
            // On success, let the user simply retry the access (read_page won't
            // create the PTE, so strictly speaking this adds overhead).
            return object->ops->read_page(object->ops_ud, offset) >= 0;
        }
    }

    // There is a page in the backing layer, so reference it.
    if (!page_u && page_l) {
        if (write) {
            // Map the page from the lower layer if present.
            page_u = vm_resident_share_page(resident, offset, page_l);
            if (!page_u)
                return false; // OOM
        } else {
            // We can read from it. We must not set it up for COW, because we're
            // still supposed see see foreign writes into the backing store. (So
            // just R/O map it; don't make it part of the upper vm_resident.)
            page_u = page_l;
            allow_write = false;
        }
    }

    if (!page_u)
        return false; // (can this even happen)

    if (write && !vm_resident_make_writable(page_u))
        return false; // OOM

    allow_write &= vm_resident_is_writable(page_u);

    int map_flags = MMU_FLAG_RMAP;
    if ((m->flags & KERN_MAP_PERM_W) && allow_write)
        map_flags |= MMU_FLAG_W;
    if (m->flags & KERN_MAP_PERM_R)
        map_flags |= MMU_FLAG_R;
    if (m->flags & KERN_MAP_PERM_X)
        map_flags |= MMU_FLAG_X;

    printf("map %p: %p -> %lx 0x%x\n", as->mmu, (void *)iaddr, (long)page_u->phys_addr, map_flags);
    return mmu_map(as->mmu, (void *)iaddr, page_u->phys_addr, PAGE_SIZE, map_flags);
}

uint64_t vm_aspace_get_phys(struct vm_aspace *as, void *addr, int access)
{
    if (!vm_aspace_handle_page_fault(as, addr, access))
        return INVALID_PHY_ADDR;

    uint64_t phys;
    size_t ps;
    int flags;

    if (!mmu_read_entry(as->mmu, addr, &phys, &ps, &flags))
        return INVALID_PHY_ADDR;

    if (phys == INVALID_PHY_ADDR) {
        // At least one code path forces a "retry". This is normally reasonably
        // transparent, but is annoying for this function.
        if (!vm_aspace_handle_page_fault(as, addr, access))
            return INVALID_PHY_ADDR;

        mmu_read_entry(as->mmu, addr, &phys, &ps, &flags);

        // Should not happen, especially because there's no concurrency within
        // the kernel.
        assert(phys != INVALID_PHY_ADDR);
    }

    return phys;
}
