#include "handle.h"
#include "kernel.h"
#include "memory.h"
#include "mmu.h"
#include "page_alloc.h"
#include "thread.h"

#include <kernel/syscalls.h>

// Require that struct handle is evenly divisible by PAGE_SIZE. This makes some
// things less of a pain due to the virtual address space mapping. It prevents
// that a struct handle can stride a page boundary.
static_assert(PAGE_SIZE / sizeof(struct handle) *
              sizeof(struct handle) == PAGE_SIZE, "");

#define HANDLE_TABLE ((struct handle *)HANDLE_TABLE_BASE)
#define MAX_HANDLES (HANDLE_TABLE_SIZE / sizeof(struct handle))

// Handle 0 is reserved for the freelist.
#define HANDLES_FREE_LIST (HANDLE_TABLE[0].u.invalid.next)
#define HANDLES_ALLOCATED_SIZE (HANDLE_TABLE[0].u.invalid.allocated_size)
static_assert(KERN_HANDLE_INVALID < 1, "");

static const struct handle_vtable *handle_vtable[HANDLE_TYPE_COUNT] = {
    [HANDLE_TYPE_THREAD] = &handle_thread,
};

// Allocate a page at the given page aligned offset and initialize it.
static bool allocate_handle_page(struct mmu *mmu, size_t offset)
{
    MMU_ASSERT_CURRENT(mmu);

    if (offset >= HANDLE_TABLE_SIZE)
        return false;

    uint64_t phys = page_alloc_phy(1, PAGE_USAGE_HTABLE);
    if (phys == INVALID_PHY_ADDR)
        return false; // OOM

    if (!mmu_map(mmu, (void *)(HANDLE_TABLE_BASE + offset), phys, PAGE_SIZE,
                 MMU_FLAG_RW | MMU_FLAG_PS | MMU_FLAG_NEW))
    {
        page_free_phy(phys, 1);
        return false; // OOM, probably
    }

    memset((void *)(HANDLE_TABLE_BASE + offset), 0, PAGE_SIZE);

    struct handle *first = &HANDLE_TABLE[offset / sizeof(struct handle)];
    struct handle *end = first + PAGE_SIZE / sizeof(struct handle);
    if (offset == 0)
        first++; // reserve handle 0 for freelist root
    // Make some effort to add them in order for cosmetic reasons.
    struct handle **p_prev = &HANDLES_FREE_LIST;
    assert(!*p_prev);
    for (struct handle *cur = first; cur != end; cur++) {
        *p_prev = cur;
        p_prev = &cur->u.invalid.next;
    }

    HANDLES_ALLOCATED_SIZE = offset + PAGE_SIZE;
    return true;
}

static void read_handle_type_lower(void *ctx)
{
    void **args = ctx;
    *(int *)args[1] = ((struct handle *)args[0])->type;
}

// Return h->type. If h was not mapped, return -1.
static int read_handle_type(struct handle *h)
{
    int res = -1;
    void *args[2] = {h, &res};
    return run_trap_pagefaults(HANDLE_TABLE_BASE,
                               HANDLE_TABLE_BASE + HANDLE_TABLE_SIZE - 1,
                               read_handle_type_lower, args)
        ? res : -1;
}

bool handle_table_create(struct mmu *mmu)
{
    MMU_ASSERT_CURRENT(mmu);

    if (read_handle_type(&HANDLE_TABLE[0]) == 0)
        return true;

    return allocate_handle_page(mmu, 0);
}

void handle_table_destroy(struct mmu *mmu)
{
    MMU_ASSERT_CURRENT(mmu);

    if (read_handle_type(&HANDLE_TABLE[0]) < 0)
        return; // nothing ever allocated

    size_t size = HANDLES_ALLOCATED_SIZE;

    for (size_t offset = 0; offset < size; offset += PAGE_SIZE) {
        void *vaddr = (void *)(HANDLE_TABLE_BASE + offset);
        uint64_t phys;
        size_t page_size;
        int flags;
        mmu_read_entry(mmu, vaddr, &phys, &page_size, &flags);
        assert(phys != INVALID_PHY_ADDR);
        page_free_phy(phys, 1);
        bool r = mmu_map(mmu, vaddr, INVALID_PHY_ADDR, PAGE_SIZE, MMU_FLAG_PS);
        assert(r);
    }
}

int64_t handle_get_id(struct handle *h)
{
    if (!h)
        return KERN_HANDLE_INVALID;
    assert(h >= &HANDLE_TABLE[0] && h < &HANDLE_TABLE[MAX_HANDLES]);
    return h - &HANDLE_TABLE[0];
}

struct handle *handle_lookup(int64_t handle)
{
    MMU_ASSERT_CURRENT(thread_get_mmu(thread_current()));

    if (handle < 0 || handle >= MAX_HANDLES)
        return NULL;

    struct handle *h = &HANDLE_TABLE[handle];

    // (The idea is that this could be very fast in ASM "fast path" code, where
    // you'd just do the access, page faults would work similar to table-driven
    // exception handling, i.e. zero-cost if no page fault happens. This is much
    // faster than read_handle_type(), which has a lot of call overhead. It
    // seemed like a great idea in theory, but while I was writing this I
    // thought, what the fuck is this stupid idea just to avoid a comparison op
    // in a fast path that will never exist? It also makes some things really
    // messy because you need to switch address spaces to modify the handle
    // table of another process. But whatever.)
    return read_handle_type(h) <= 0 ? NULL : h;
}

struct handle *handle_lookup_type(int64_t handle, enum handle_type type)
{
    struct handle *h = handle_lookup(handle);
    return h && h->type == type ? h : NULL;
}

struct handle *handle_alloc(void)
{
    MMU_ASSERT_CURRENT(thread_get_mmu(thread_current()));

    if (!HANDLES_FREE_LIST) {
        struct mmu *mmu = thread_get_mmu(thread_current());
        if (!allocate_handle_page(mmu, HANDLES_ALLOCATED_SIZE))
            return NULL;
    }

    assert(HANDLES_FREE_LIST);

    struct handle *new = HANDLES_FREE_LIST;
    HANDLES_FREE_LIST = new->u.invalid.next;
    return new;
}

void handle_free(struct handle *h)
{
    MMU_ASSERT_CURRENT(thread_get_mmu(thread_current()));

    assert(h >= &HANDLE_TABLE[0] && h < &HANDLE_TABLE[MAX_HANDLES]);

    handle_vtable[h->type]->unref(h);

    h->type = HANDLE_TYPE_INVALID;
    h->u.invalid.next = HANDLES_FREE_LIST;
    HANDLES_FREE_LIST = h;

    // Note: if there are too many free handles, we should probably compactify
    //       the handle table and free unused pages. Since that is expensive,
    //       it would actually better to leave this to some sort of background
    //       cleanup task or global OOM handling mechanism.
}

int64_t handle_add_or_free(struct handle *val)
{
    if (val->type == HANDLE_TYPE_INVALID)
        return KERN_HANDLE_INVALID;
    struct handle *new = handle_alloc();
    if (!new || !handle_vtable[val->type]->ref(new, val)) {
        handle_vtable[val->type]->unref(val);
        return KERN_HANDLE_INVALID;
    }
    return handle_get_id(new);
}
