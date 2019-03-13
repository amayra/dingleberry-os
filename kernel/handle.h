#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// NOTE: as some sort of micro-optimizations, the handle table uses a fixed size
//       virtual address space region starting at HANDLE_TABLE_BASE (with the
//       size HANDLE_TABLE_SIZE). This is per userspace address-space; thus
//       all pointers into this handle table (usually struct handle) are valid
//       only if the corresponding address space is current.
//
// Unless otherwise noted, all handle_* functions require that the correct
// process address space is current. Changing the address space will make
// handle* pointer located in the handle table invalid.

enum handle_type {
    HANDLE_TYPE_INVALID = 0,
    HANDLE_TYPE_THREAD,

    HANDLE_TYPE_COUNT // not a valid type
};

struct handle {
    uint8_t type;

    union {
        // HANDLE_TYPE_INVALID
        struct {
            // Internal freelist, or for handle 0, the freelist root.
            struct handle *next;
            // For handle 0: size of the allocated part of the handle table.
            size_t allocated_size;
        } invalid;

        // HANDLE_TYPE_THREAD
        struct thread *thread;
    } u;

    size_t pad0;
};

struct mmu;

// Make sure the first handle page is allocated, so that the freelist works.
// mmu must be provided for messy reasons. It must be the current address space
// while the function is called.
// Idempotent, returns success.
bool handle_table_create(struct mmu *mmu);

// Free the handle table in the current address space (if any).
// The mmu parameter works as in handle_table_create().
void handle_table_destroy(struct mmu *mmu);

// Return ID. h must be a pointer into t, or NULL. This works with any address
// space, and *h is not dereferenced.
int64_t handle_get_id(struct handle *h);

// Lookup handle by ID. Returns NULL if the id is not a valid handle.
struct handle *handle_lookup(int64_t id);

// Lookup a handle by ID and type. Returns NULL if no ID invalid or wrong type.
struct handle *handle_lookup_type(int64_t id, enum handle_type type);

// Add an initially invalid handle. Returns NULL if not found.
struct handle *handle_alloc(void);

// Free the handle. There is no protection against double frees.
void handle_free(struct handle *h);

// Same as handle_alloc, but fill the new handle with *val. If handle allocation
// fails, the handle data in *val is unreferenced.
// This returns an ID as used in userspace.
int64_t handle_add_or_free(struct handle *val);

// Pass explicit mmu pointer, which enables you to allocate a handle in a
// specific address space by temporary switching (instead of needing to change
// the current thread).
struct handle *handle_alloc_on(struct mmu *mmu);
int64_t handle_add_or_free_on(struct mmu *mmu, struct handle *val);
void handle_free_on(struct mmu *mmu, struct handle *h);

void handle_dump_all(void);

struct handle_vtable {
    bool (*ref)(struct handle *new, struct handle *old);
    void (*unref)(struct handle *h);
    const char *name;
};

extern const struct handle_vtable handle_thread;
