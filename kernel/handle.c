#include "handle.h"
#include "kernel.h"
#include "kmalloc.h"
#include "memory.h"
#include "mmu.h"
#include "page_alloc.h"
#include "thread.h"
#include "thread_internal.h"
#include "virtual_memory.h"

#include <kernel/api.h>

// Reserve entry 0 for freelist.
static_assert(KERN_HANDLE_INVALID < 1, "");

const struct handle_vtable *handle_vtable[HANDLE_TYPE_COUNT] = {
    [HANDLE_TYPE_THREAD] = &handle_thread,
    [HANDLE_TYPE_IPC_LISTENER] = &handle_ipc_listener,
    [HANDLE_TYPE_IPC_TARGET] = &handle_ipc_target,
    [HANDLE_TYPE_IPC_REPLY] = &handle_ipc_reply,
};

#define handle_freelist_ptr(t) (&(t)->handle_table.handles[0].u.invalid.next)

// struct handle_table is duplicated in every thread struct for the sake of
// locality of memory accesses (micro-optimization). This is called to resync
// the table if anything has changed. This should be rare, as the contents
// change only when the table is resized.
static void sync_handle_tables(struct thread *t, struct handle_table table)
{
    struct vm_aspace_owners *list = vm_aspace_get_owners(t->aspace);
    for (struct thread *t2 = list->head; t2; t2 = t2->aspace_siblings.next)
        t2->handle_table = table;
}

static bool extend_handle_table(struct thread *t)
{
    struct handle_table table = t->handle_table;

    // Call only if there are no free handles.
    assert(!table.num_handles || !table.handles[0].u.invalid.next);

    size_t new_count = MAX(16, table.num_handles) * 2;
    if (new_count > (size_t)-1 / sizeof(struct handle))
        return false;

    table.handles = reallocz(table.handles, new_count * sizeof(struct handle));
    if (!table.handles)
        return false;

    // Note: first entry is reserved for freelist root.
    struct handle **p_prev = &table.handles[0].u.invalid.next;
    for (size_t n = MAX(1, table.num_handles); n < new_count; n++) {
        struct handle *h = &table.handles[n];
        if (h->type == HANDLE_TYPE_INVALID) {
            // Make some effort to add them in order for cosmetic reasons.
            *p_prev = h;
            p_prev = &h->u.invalid.next;
        }
    }
    *p_prev = NULL;

    table.num_handles = new_count;
    sync_handle_tables(t, table);

    return true;
}

bool handle_table_create(struct thread *t)
{
    if (t->handle_table.num_handles)
        return true;

    return extend_handle_table(t);
}

void handle_table_destroy(struct thread *t)
{
    for (size_t n = 1; n < t->handle_table.num_handles; n++) {
        struct handle *h = &t->handle_table.handles[n];
        if (h->type != HANDLE_TYPE_INVALID && h->type != HANDLE_TYPE_RESERVED)
            handle_vtable[h->type]->unref(h);
    }

    free(t->handle_table.handles);
    t->handle_table.handles = NULL;
    t->handle_table.num_handles = 0;
    sync_handle_tables(t, t->handle_table);
}

kern_handle handle_get_id(struct thread *t, struct handle *h)
{
    if (!h)
        return KERN_HANDLE_INVALID;
    assert(h >= &t->handle_table.handles[0] &&
           h < &t->handle_table.handles[t->handle_table.num_handles]);
    return h - &t->handle_table.handles[0];
}

struct handle *handle_lookup(struct thread *t, kern_handle handle)
{
    if (handle < 0 || handle >= t->handle_table.num_handles)
        return NULL;

    struct handle *h = &t->handle_table.handles[handle];
    return h->type != HANDLE_TYPE_INVALID && h->type != HANDLE_TYPE_RESERVED
           ? h : NULL;
}

struct handle *handle_lookup_type(struct thread *t, kern_handle handle, enum handle_type type)
{
    struct handle *h = handle_lookup(t, handle);
    return h && h->type == type ? h : NULL;
}

struct handle *handle_alloc(struct thread *t)
{
    struct handle *new = *handle_freelist_ptr(t);
    if (!new) {
        if (!extend_handle_table(t))
            return NULL;
        new = *handle_freelist_ptr(t);
    }

    assert(new);

    *handle_freelist_ptr(t) = new->u.invalid.next;
    return new;
}

void handle_free(struct thread *t, struct handle *h)
{
    assert(h >= &t->handle_table.handles[0] &&
           h < &t->handle_table.handles[t->handle_table.num_handles]);
    assert(h->type != HANDLE_TYPE_INVALID);

    if (h->type != HANDLE_TYPE_RESERVED)
        handle_vtable[h->type]->unref(h);

    h->type = HANDLE_TYPE_INVALID;
    h->u.invalid.next = *handle_freelist_ptr(t);
    *handle_freelist_ptr(t) = h;

    handle_dump_all(t);

    // Note: if there are too many free handles, we should probably compactify
    //       the handle table and free unused pages. Since that is expensive,
    //       it would possibly be better to leave this to some sort of background
    //       cleanup task or global OOM handling mechanism.
}

kern_handle handle_add_or_free(struct thread *t, struct handle *val)
{
    if (val->type == HANDLE_TYPE_INVALID)
        return KERN_HANDLE_INVALID;
    struct handle *new = handle_alloc(t);
    if (!new || !handle_vtable[val->type]->ref(new, val)) {
        handle_vtable[val->type]->unref(val);
        handle_free(t, new);
        return KERN_HANDLE_INVALID;
    }
    handle_dump_all(t);
    return handle_get_id(t, new);
}

void handle_dump_all(struct thread *t)
{
    if (!t->handle_table.num_handles) {
        printf("No handle table allocated.\n");
        return;
    }

    for (size_t n = 0; n < t->handle_table.num_handles; n++) {
        struct handle *h = &t->handle_table.handles[n];

        if (h->type && h->type != HANDLE_TYPE_RESERVED)
            printf("%zu: %s\n", n, handle_vtable[h->type]->name);
    }
    printf("Space for %zu handles allocated.\n", t->handle_table.num_handles);
}
