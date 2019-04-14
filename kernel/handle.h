#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <kernel/api.h>

enum handle_type {
    HANDLE_TYPE_INVALID = 0,
    HANDLE_TYPE_THREAD,
    HANDLE_TYPE_IPC_TARGET,
    HANDLE_TYPE_IPC_REPLY,
    HANDLE_TYPE_IPC_LISTENER,

    // Like _INVALID, but not in the main free-list. Don't touch.
    HANDLE_TYPE_RESERVED,

    HANDLE_TYPE_COUNT // not a valid type
};

// Note: some fields (freelist and IPC handles) are accessed by asm.
struct handle {
    uint8_t type;

    union {
        // HANDLE_TYPE_INVALID
        struct {
            // Internal freelist, or for handle 0, the freelist root.
            struct handle *next;
        } invalid;

        // HANDLE_TYPE_THREAD
        struct thread *thread;

        // HANDLE_TYPE_IPC_LISTENER
        struct {
            struct ipc_listener *listener;
        } ipc_listener;

        // HANDLE_TYPE_IPC_TARGET
        struct {
            struct ipc_listener *listener;
            uintptr_t user_data;
        } ipc_target;

        // HANDLE_TYPE_IPC_REPLY
        struct {
            // Note: the thread is always in THREAD_STATE_WAIT_IPC_REPLY. See
            //       there for important invariants. One consequence is that
            //       the reply handle can't be duplicated.
            struct thread *caller;
        } ipc_reply;

        // HANDLE_TYPE_RESERVED
        // -

    } u;

    size_t pad0;
};

#define HANDLE_SIZE_LOG 5

struct handle_table {
    struct handle *handles;     // valid in handles[0..num_handles-1].
    size_t num_handles;         // allocated size of handles[]
};

struct thread;

// Make sure the first handle page is allocated, so that the freelist works.
bool handle_table_create(struct thread *t);

// Free the handle table in the current address space (if any).
void handle_table_destroy(struct thread *t);

// Return ID. h must be a pointer into thread's table, or NULL.
kern_handle handle_get_id(struct thread *t, struct handle *h);

// Lookup handle by ID. Returns NULL if the id is not a valid handle.
struct handle *handle_lookup(struct thread *t, kern_handle id);

// Lookup a handle by ID and type. Returns NULL if no ID invalid or wrong type.
// This _does_ work with HANDLE_TYPE_RESERVED as a special case.
struct handle *handle_lookup_type(struct thread *t, kern_handle id,
                                  enum handle_type type);

// Add an initially invalid handle. Returns NULL if not found.
// This may invalidate existing handle pointers.
struct handle *handle_alloc(struct thread *t);

// Free the handle. There is no protection against double frees.
void handle_free(struct thread *t, struct handle *h);

// Same as handle_alloc, but fill the new handle with *val. If handle allocation
// fails, the handle data in *val is unreferenced.
// *val must have refcount 1 (conceptually).
// This returns an ID as used in userspace.
// This calls handle_alloc() and may invalidate handle pointers.
kern_handle handle_add_or_free(struct thread *t, struct handle *val);

void handle_dump_all(struct thread *t);

struct handle_vtable {
    bool (*ref)(struct handle *new, struct handle *old);
    void (*unref)(struct handle *h);
    const char *name;
};

extern const struct handle_vtable handle_thread;
extern const struct handle_vtable handle_ipc_listener;
extern const struct handle_vtable handle_ipc_target;
extern const struct handle_vtable handle_ipc_reply;

extern const struct handle_vtable *handle_vtable[HANDLE_TYPE_COUNT];
