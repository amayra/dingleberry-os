#include <stdalign.h>

#include <linked_list.h>

#include "kernel.h"
#include "page_alloc.h"
#include "slob.h"

#define SLOBBY_MAGIC 0xB00BAFFE

// Per-page meta-data. It is located at the end of the page, as this seems to
// make dealing with element alignment simpler.
struct slobby {
    struct {
        struct slobby *prev, *next;
    } slob_list;
    uint32_t magic;         // SLOBBY_MAGIC
    uint16_t num_free;      // number of free elements
    // Free bit for each item. At first I wanted to use a linked list of free
    // item (using the item memory itself for the list node), but then my brain
    // humiliated me into obsessing about double-free bugs: if we had no meta-
    // data per _allocated_ item, then we couldn't even detect double-frees.
    // Bitmaps are probably pretty ideal for low item counts anyway, if they are
    // used the right way (which we don't).
    uint32_t freemap[];
};

void slob_init(struct slob *slob, size_t element_size)
{
    *slob = (struct slob){
        .element_size = element_size,
        .num_per_slobby = (PAGE_SIZE - sizeof(struct slobby)) / element_size,
    };

    // Bitmap size depends on the number of items.
    while (1) {
        slob->meta_size = sizeof(struct slobby) +
                          (slob->num_per_slobby + 31) / 32 * 4;
        // Guarantee alignment for slobby.
        while (slob->meta_size & (alignof(struct slobby) - 1))
            slob->meta_size++;
        size_t total_size =
            element_size * slob->num_per_slobby + slob->meta_size;
        if (total_size <= PAGE_SIZE || !slob->num_per_slobby)
            break;
        slob->num_per_slobby--;
    }

    assert(slob->num_per_slobby); // element_size close to PAGE_SIZE?
}

void allocate_slobby_page(struct slob *slob)
{
    void *p = page_alloc(PAGE_SIZE, PAGE_USAGE_SLOBBY);
    if (!p)
        return;

    memset(p, 0xDE, PAGE_SIZE); // half-assed memory poisoning/checking

    struct slobby *s = (void *)((char *)p + PAGE_SIZE - slob->meta_size);

    *s = (struct slobby) {
        .magic = SLOBBY_MAGIC,
        .num_free = slob->num_per_slobby,
    };

    // Set free bits (explicitly ensure trailing bits are cleared).
    memset(s + 1, 0, slob->meta_size - sizeof(s));
    for (size_t n = 0; n < slob->num_per_slobby; n++)
        s->freemap[n  / 32] |= 1U << (n % 32);

    LL_APPEND(slob_list, &slob->free_list, s);

    return;
}

void *slob_allocz(struct slob *slob)
{
    if (!slob->free_list.head)
        allocate_slobby_page(slob);
    struct slobby *s = slob->free_list.head;
    if (!s)
        return NULL;

    assert(s->magic == SLOBBY_MAGIC);
    assert(s->num_free > 0);

    size_t index = slob->num_per_slobby;

    for (size_t n = 0; n < slob->num_per_slobby; n += 32) {
        // Could use __builtin_ffsl here.
        uint32_t v = s->freemap[n / 32];
        if (v) {
            for (size_t b = 0; b < 32; b++) {
                if (v & (1U << b)) {
                    index = n + b;
                    goto done;
                }
            }
        }
    }
    done:;

    assert(index < slob->num_per_slobby); // must have found something

    s->freemap[index / 32] &= ~(uint32_t)(1U << (index % 32));
    s->num_free -= 1;

    if (!s->num_free)
        LL_REMOVE(slob_list, &slob->free_list, s);

    uint8_t *p = (uint8_t *)s + slob->meta_size - PAGE_SIZE;
    uint8_t *e = p + slob->element_size * index;

    // half-assed memory poisoning/checking
    for (size_t n = 0; n < slob->element_size; n++)
        assert(e[n] == 0xDE);

    memset(e, 0, slob->element_size);
    return e;
}

void slob_free(struct slob *slob, void *ptr)
{
    if (!ptr)
        return;

    memset(ptr, 0xDE, slob->element_size); // half-assed memory poisoning

    size_t offset = (uintptr_t)ptr & (PAGE_SIZE - 1);

    char *p = (char *)ptr - offset;
    struct slobby *s = (void *)(p + PAGE_SIZE - slob->meta_size);

    assert(s->magic == SLOBBY_MAGIC);
    assert(s->num_free < slob->num_per_slobby);

    size_t index = offset / slob->element_size;
    assert(index < slob->num_per_slobby);

    assert(!(s->freemap[index / 32] & 1U << (index % 32))); // double free

    s->freemap[index / 32] |= 1U << (index % 32);
    s->num_free += 1;

    if (s->num_free == 1)
        LL_APPEND(slob_list, &slob->free_list, s);
}

void slob_free_unused(struct slob *slob)
{
    // Could be made O(1) (for low number of fully free slobs, n = total slobs)
    // by putting all fully free slobs into a list.
    struct slobby *s = slob->free_list.head;
    while (s) {
        struct slobby *next = s->slob_list.next;
        if (s->num_free == slob->num_per_slobby) {
            LL_REMOVE(slob_list, &slob->free_list, s);

            uint8_t *p = (uint8_t *)s + slob->meta_size - PAGE_SIZE;

            // half-assed memory poisoning/checking
            for (size_t n = 0; n < PAGE_SIZE - slob->meta_size; n++)
                assert(p[n] == 0xDE);

            page_free(p, PAGE_SIZE);
        }
        s = next;
    }
}
