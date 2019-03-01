#include "kernel.h"
#include "page_alloc.h"
#include "page_internal.h"

// Support only a single RAM region, but no need to do anything more advanced.
// RAM rages can be "reserved" to account for small holes and unusable regions.

// Limited by the static size of ram_pages[] and the initial physical mapping.
// This is _very_ wasteful as it bloats ram_pages[] with possibly useless
// entries. (Both limits could be trivially removed if you didn't have to care
// about boot.)
#define MAX_RAM (256ULL * 1024 * 1024)
static_assert(MAX_RAM <= BOOT_PHY_MAP_SIZE, "");

static uint64_t ram_base_phy = INVALID_PHY_ADDR;
static uint64_t ram_base_pn;
static uint64_t ram_num_pages;

// Per-page meta data. Used by other subsystems too.
static struct phys_page ram_pages[(MAX_RAM + PAGE_SIZE - 1) / PAGE_SIZE];

enum {
    PAGE_FLAG_BEGIN = 1 << 0,       // start of allocation range
    PAGE_FLAG_END   = 1 << 1,       // end of allocation range
};
static_assert(PAGE_USAGE_COUNT <= 0xFF, "");

struct phys_page *phys_page_get(uint64_t phys_addr)
{
    if (phys_addr < ram_base_phy)
        return NULL;

    size_t pn = (phys_addr - ram_base_phy) / PAGE_SIZE;
    if (pn >= ram_num_pages)
        return NULL;

    return &ram_pages[pn];
}

// Mark a range of pages with new_usage. Also, verify that the same pages had
// old_usage before, and check and set range begin/end markers as appropriate
// (for debugging).
static void mark_pages(uint64_t pn_start, uint64_t pn_end, uint8_t old_usage,
                       uint8_t new_usage)
{
    // Questionable stuff for early boot.
    bool mark_resv = old_usage == PAGE_USAGE_FREE &&
                     new_usage == PAGE_USAGE_RESERVED;

    if (ram_base_phy == INVALID_PHY_ADDR) {
        assert(mark_resv);
        return;
    }

    if (pn_start < ram_base_pn) {
        assert(mark_resv);
        pn_start = ram_base_pn;
    }
    if (pn_end > ram_base_pn + ram_num_pages) {
        assert(mark_resv);
        pn_end = ram_base_pn + ram_num_pages;
    }

    if (pn_start >= pn_end)
        return;

    pn_start -= ram_base_pn;
    pn_end -= ram_base_pn;

    for (size_t n = pn_start; n < pn_end; n++) {
        uint8_t rflags = 0;
        if (n == pn_start)
            rflags |= PAGE_FLAG_BEGIN;
        if (n + 1 == pn_end)
            rflags |= PAGE_FLAG_END;

        uint8_t new_flags = 0;
        uint8_t old_flags = 0;

        if (new_usage != PAGE_USAGE_FREE && new_usage != PAGE_USAGE_RESERVED)
            new_flags |= rflags;

        if (old_usage != PAGE_USAGE_FREE && old_usage != PAGE_USAGE_RESERVED)
            old_flags |= rflags;

        if (mark_resv) {
            // Marking reserved pages as reserved is allowed, even if old_usage
            // is USAGE_PAGE_FREE.
            assert(ram_pages[n].usage == PAGE_USAGE_RESERVED ||
                   ram_pages[n].usage == PAGE_USAGE_FREE);
        } else {
            assert(ram_pages[n].usage == old_usage);
        }

        assert(ram_pages[n].pa_flags == old_flags);

        // Reset meta data on changes (i.e. alloc/dealloc).
        if (ram_pages[n].usage != new_usage) {
            ram_pages[n].u_flags = 0;
            memset(&ram_pages[n].u, 0, sizeof(ram_pages[n].u));
        }

        ram_pages[n].usage = new_usage;
        ram_pages[n].pa_flags = new_flags;
    }
}

void page_alloc_mark(uint64_t start, uint64_t size, enum page_usage usage)
{
    if (!size || ram_base_phy == INVALID_PHY_ADDR)
        return;

    // The region can end on 2^64, but not after.
    assert(UINT64_MAX - start >= size - 1);

    uint64_t pn_start = start / PAGE_SIZE;
    uint64_t pn_end = (start + size) / PAGE_SIZE;
    if ((start + size) & (PAGE_SIZE - 1))
        pn_end++;

    mark_pages(pn_start, pn_end, PAGE_USAGE_FREE, usage);
}

void page_alloc_get_ram(int index, uint64_t *base, uint64_t *size)
{
    *base = 0;
    *size = 0;

    // This implementation supports only one range.
    if (index != 0 || ram_base_phy == INVALID_PHY_ADDR)
        return;

    *base = ram_base_phy;
    *size = ram_num_pages * PAGE_SIZE;
}

bool page_alloc_add_ram(uint64_t base_phy, uint64_t size)
{
    if (!size)
        return true;

    if (base_phy & (PAGE_SIZE - 1))
        panic("unaligned RAM base\n");
    if (size & (PAGE_SIZE - 1))
        panic("unaligned RAM size\n");

    if (ram_base_phy != INVALID_PHY_ADDR) {
        printf("Only 1 RAM region is supported at the time.\n");
        return false;
    }

    if (size > MAX_RAM) {
        printf("Lager than MAX_RAM, ignoring some RAM.\n");
        size = MAX_RAM;
    }

    ram_base_phy = base_phy;
    ram_base_pn = base_phy / PAGE_SIZE;
    ram_num_pages = size / PAGE_SIZE;

    mark_pages(ram_base_pn, ram_num_pages, PAGE_USAGE_FREE, PAGE_USAGE_FREE);

    return true;
}

// Whitelist usages for dynamic memory allocation.
static bool check_usage(enum page_usage usage)
{
    switch (usage) {
    case PAGE_USAGE_GENERAL:
    case PAGE_USAGE_GENERAL_2:
    case PAGE_USAGE_GENERAL_3:
    case PAGE_USAGE_SLOBBY:
    case PAGE_USAGE_PT:
    case PAGE_USAGE_THREAD:
    case PAGE_USAGE_USER:
    case PAGR_USAGE_KMALLOC:
        return true;
    default:
        return false;
    }
}

uint64_t page_alloc_phy(size_t num_pages, enum page_usage usage)
{
    if (!num_pages)
        return INVALID_PHY_ADDR;

    assert(check_usage(usage));

    size_t cur_pn = 0;
    size_t cur_num = 0;

    // Linear scan over the full memory (this is a high performance kernel!)
    for (size_t n = 0; n < ram_num_pages; n++) {
        if (!ram_pages[n].usage) {
            if (!cur_num)
                cur_pn = n;
            cur_num++;
            if (cur_num == num_pages) {
                uint64_t r_pn = ram_base_pn + cur_pn;
                mark_pages(r_pn, r_pn + cur_num, PAGE_USAGE_FREE, usage);
                return r_pn * PAGE_SIZE;
            }
        } else {
            cur_num = 0;
        }
    }

    page_alloc_debug_dump();
    return INVALID_PHY_ADDR;
}

void page_free_phy(uint64_t addr, size_t num_pages)
{
    if (addr == INVALID_PHY_ADDR && !num_pages)
        return;

    assert(addr != INVALID_PHY_ADDR && num_pages);
    assert(!(addr & (PAGE_SIZE - 1)));

    uint64_t pn = addr / PAGE_SIZE;

    assert(pn >= ram_base_pn);
    assert(pn < ram_base_pn + ram_num_pages);

    uint64_t end_pn = pn + num_pages;
    assert(end_pn > pn);
    assert(end_pn <= ram_base_pn + ram_num_pages);

    uint8_t flags = ram_pages[pn - ram_base_pn].usage;
    // Must be an allocated page & not trying to free memory page_alloc_phy()
    // didn't allocate.
    assert(check_usage(flags));

    mark_pages(pn, end_pn, flags, PAGE_USAGE_FREE);
}

void *page_phys_to_virt(uint64_t addr)
{
    if (addr >= ram_base_phy && (addr - ram_base_phy) < ram_num_pages * PAGE_SIZE)
        return (void *)(uintptr_t)(KERNEL_PHY_BASE + addr);
    return NULL;
}

void *page_alloc(size_t size, enum page_usage usage)
{
    if (size >= UINT64_MAX - PAGE_SIZE)
        return NULL;

    uint64_t phy = page_alloc_phy((size + PAGE_SIZE - 1) / PAGE_SIZE, usage);
    if (phy == INVALID_PHY_ADDR)
        return NULL;

    void *virt = page_phys_to_virt(phy);
    assert(virt); // is guaranteed due to matching limits
    return virt;
}

void page_free(void *addr, size_t size)
{
    if (!addr && !size)
        return;

    assert(addr && size);
    assert((uintptr_t)addr >= KERNEL_PHY_BASE);

    uint64_t phy_addr = (uintptr_t)addr - KERNEL_PHY_BASE;
    page_free_phy(phy_addr, (size + PAGE_SIZE - 1) / PAGE_SIZE);
}

void page_alloc_debug_dump(void)
{
    printf("RAM page allocator state:\n");

    if (ram_base_phy == INVALID_PHY_ADDR) {
        printf("No RAM.\n");
        return;
    }

    printf("RAM located at 0x%llx size 0x%llx.\n", (long long)ram_base_phy,
           (PAGE_SIZE * (long long)ram_num_pages));

    // Print a RAM memory map.
    int cur_usage = -1;
    int cur_pn = -1;
    int cur_num = 0;
    for (size_t n = 0; n <= ram_num_pages; n++) {
        int usage = n == ram_num_pages ? -1 : ram_pages[n].usage;
        if (usage != cur_usage) {
            if (cur_pn >= 0) {
                const char *t = "?";
                switch (cur_usage) {
                case PAGE_USAGE_FREE:       t = "free"; break;
                case PAGE_USAGE_RESERVED:   t = "firmware/boot reserved"; break;
                case PAGE_USAGE_KERNEL:     t = "kernel image"; break;
                case PAGE_USAGE_GENERAL:    t = "used"; break;
                case PAGE_USAGE_GENERAL_2:  t = "general2"; break;
                case PAGE_USAGE_GENERAL_3:  t = "general3"; break;
                case PAGE_USAGE_SLOBBY:     t = "slobby"; break;
                case PAGE_USAGE_PT:         t = "pagetable"; break;
                case PAGE_USAGE_THREAD:     t = "thread+stack"; break;
                case PAGE_USAGE_USER:       t = "user"; break;
                case PAGR_USAGE_KMALLOC:    t = "kmalloc"; break;
                }
                printf(" - %d (%d pages): %s\n", cur_pn, cur_num, t);
            }
            cur_usage = usage;
            cur_pn = n;
            cur_num = 0;
        }
        cur_num++;
    }

    // Verify range flags.
    int last_usage = -1;
    for (size_t n = 0; n < ram_num_pages; n++) {
        uint8_t flags = ram_pages[n].pa_flags;
        uint8_t usage = ram_pages[n].usage;
        if (usage == PAGE_USAGE_FREE || usage == PAGE_USAGE_RESERVED) {
            // These page types don't use the range flags.
            assert(!flags);
            // But pretend they do, for the sake of the logic below.
            flags |= PAGE_FLAG_BEGIN | PAGE_FLAG_END;
        }
        // Usage type changed, or previous page has FLAG_END => range boundary
        if (last_usage != usage) {
            assert(last_usage < 0); // must have set FLAG_END
            assert(flags & PAGE_FLAG_BEGIN);
        }
        last_usage = flags & PAGE_FLAG_END ? -1 : usage;
        // Last page must be a range end.
        if (n == ram_num_pages - 1)
            assert(flags & PAGE_FLAG_END);
    }
}
