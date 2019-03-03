#include <stdatomic.h>

#include "kernel.h"
#include "kmalloc.h"
#include "memory.h"
#include "page_alloc.h"
#include "slob.h"

#define MAX_SIZE ((size_t)-1 / 2)

// (includes header overhead)
#define BINS_BASE_SIZE_LOG 5
#define BINS_MAX_SIZE_LOG 10

// The max size should be something for which a slob page can hold more than
// 1 element of. Otherwise allocating a whole page instead is "better".
static_assert((1 << BINS_MAX_SIZE_LOG) == PAGE_SIZE / 4, "");
static_assert((1 << BINS_MAX_SIZE_LOG) <= SLOB_MAX_ELEMENT_SIZE, "");

#define NUM_BINS (BINS_MAX_SIZE_LOG - BINS_BASE_SIZE_LOG + 1)

static struct slob slobs[NUM_BINS];
static bool slobs_initialized[NUM_BINS];

#define KMALLOC_MAGIC 0x4B435553554C4F4C

struct header {
    union {
        struct {
            uint64_t magic;
            size_t size;
        };
        // Ensure adequate alignment for the allocation following this.
        // Not using max_align_t, because that doubles padding just for
        // long double, which we don't use in the kernel.
        uintmax_t align_1;
        void *align_2;
        atomic_ullong align_3;
    };
};

// Return smallest n for which (1<<n)>=v.
static unsigned log2_up(uint64_t v)
{
    for (unsigned n = 0; n < 64; n++) {
        if ((1ULL << n) >= v)
            return n;
    }
    return 64;
}

static unsigned get_bin(size_t size)
{
    unsigned log_size = log2_up(size);
    return MAX(log_size, BINS_BASE_SIZE_LOG) - BINS_BASE_SIZE_LOG;
}

void *mallocz(size_t size)
{
    if (size >= MAX_SIZE)
        return NULL;

    size += sizeof(struct header);

    void *ptr = NULL;

    if (size <= (1 << BINS_MAX_SIZE_LOG)) {
        // For sub-page allocations, we use slobs. (Less than ideal, because
        // slobs that aren't very occupied will just waste pages. Maybe a buddy
        // allocator would generally be more ideal, but at least this is simple.
        // Non-power-of-2 bins would help too and would provide an advantage
        // over a buddy allocator. But then again, for fixed sized structs you
        // should use slobs directly.)

        unsigned bin = get_bin(size);
        assert(bin < NUM_BINS);

        size = 1 << (BINS_BASE_SIZE_LOG + bin);

        if (!slobs_initialized[bin]) {
            slobs[bin] = (struct slob)SLOB_INITIALIZER_SIZE(size);
            slobs_initialized[bin] = true;
        }

        ptr = slob_allocz(&slobs[bin]);

        assert(size < PAGE_SIZE); // free() relies on this
    } else {
        // Use the page allocator for larger sizes. (Less than ideal, because
        // this allocates physically contiguous memory, which isn't a
        // requirement for kmalloc. Also, that allocator does linear scan,
        // which is slow.)

        size = (size + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

        ptr = page_alloc(size, PAGR_USAGE_KMALLOC);
        if (ptr)
            memset(ptr, 0, size);

        assert(size >= PAGE_SIZE); // free() relies on this
    }

    if (ptr) {
        struct header *h = ptr;
        *h = (struct header){
            .magic = KMALLOC_MAGIC,
            .size = size,
        };
        ptr = h + 1;
    }

    return ptr;
}

void free(void *ptr)
{
    if (!ptr)
        return;

    struct header *h = ptr;
    h--;
    assert(h->magic == KMALLOC_MAGIC);
    h->magic = 0xDEDEDEDEDEDEDEDEULL;

    size_t size = h->size;

    // memory poisoning for idiots
    memset(h, 0xDE, size);

    if (size < PAGE_SIZE) {
        unsigned bin = get_bin(size);
        assert(bin < NUM_BINS);
        assert(slobs_initialized[bin]);
        slob_free(&slobs[bin], h);
    } else {
        page_free(h, size);
    }
}

void *reallocz(void *ptr, size_t size)
{
    if (!ptr)
        return mallocz(size);

    if (!size) {
        free(ptr);
        return NULL;
    }

    struct header *h = ptr;
    h--;
    assert(h->magic == KMALLOC_MAGIC);

    size_t old_size = h->size - sizeof(struct header);

    // (if more than 1/4 gets unused, realloc)
    if (old_size >= size && size >= old_size / 4) {
        // (this is still a *z variant function)
        if (size < old_size)
            memset((char *)ptr + size, 0, old_size - size);
        return ptr;
    }

    // Actually realloc. Slobs can carry only 1 size, and page_alloc() doesn't
    // support extension (sort of, due to debug stuff), so just copy.
    void *nptr = mallocz(size);
    if (!nptr)
        return NULL;

    // (we don't know the real size, so this may copy padding)
    memcpy(nptr, ptr, MIN(old_size, size));

    free(ptr);
    return nptr;
}

void *malloc(size_t size)
{
    return mallocz(size);
}

void *realloc(void *ptr, size_t size)
{
    return reallocz(ptr, size);
}
