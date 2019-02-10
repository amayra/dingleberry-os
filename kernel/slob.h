#pragma once

#include <stddef.h>

// Simplistic slab-allocator like allocator. In truth a free list for fixed
// size blocks.
struct slob {
    // Consider all fields private. Public definition provided for static
    // allocation.
    size_t element_size;    // size of an allocation
    size_t meta_size;       // size of per-page metadata
    size_t num_per_slobby;  // size of elements on each page
    struct {
        struct slobby *head, *tail;
    } free_list;            // list of slob pages that have free items
};

// Init a slob with the given element size.
// *slob is fully overwritten for initialization.
// Explodes if the size is close to PAGE_SIZE.
// Concurrent access is not supported; the caller needs to synchronize all
// accesses to thr same slob.
void slob_init(struct slob *slob, size_t element_size);

// Allocate an object from the slob. If nothing is free, and no new page could
// be allocated, returns NULL.
// This is the z suffix variant: the memory is cleared to zero.
void *slob_allocz(struct slob *slob);

// Free an object allocated with slob_allocz. Does nothing if ptr==NULL.
void slob_free(struct slob *slob, void *ptr);

// Free unused pages.
void slob_free_unused(struct slob *slob);
