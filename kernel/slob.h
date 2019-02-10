#pragma once

#include <stddef.h>

// Simplistic slab-allocator like allocator. In truth a free list for fixed
// size blocks.
// Concurrent access is not supported; the caller needs to synchronize all
// accesses to the same slob.
struct slob {
    // Consider all fields private. Public definition provided for static
    // allocation and SLOB_INITIALIZER().
    size_t element_size;    // size of an allocation
    size_t meta_size;       // size of per-page metadata
    size_t num_per_slobby;  // size of elements on each page
    struct {
        struct slobby *head, *tail;
    } free_list;            // list of slob pages that have free items
};

// Static initializer a slob with the given data type. Actual initialization
// is done lazily. Explodes if type is too large (close to PAGE_SIZE).
#define SLOB_INITIALIZER(type) {.element_size = sizeof(type)}

// Allocate an object from the slob. If nothing is free, and no new page could
// be allocated, returns NULL.
// This is the z suffix variant: the memory is cleared to zero.
void *slob_allocz(struct slob *slob);

// Free an object allocated with slob_allocz. Does nothing if ptr==NULL.
void slob_free(struct slob *slob, void *ptr);

// Free unused pages.
void slob_free_unused(struct slob *slob);
