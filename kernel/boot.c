#include <endian.h>

#include "kernel.h"
#include "memory.h"
#include "page_alloc.h"
#include "slob.h"

extern char _start;
extern char _end;

struct fdt_header {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

struct fdt_reserve_entry {
    uint64_t address;
    uint64_t size;
};

enum fdt_tok {
    FDT_BEGIN_NODE  = 1,
    FDT_END_NODE    = 2,
    FDT_PROP        = 3,
    FDT_NOP         = 4,
    FDT_END         = 9,
};

static void append_str(char *buf, size_t max, size_t *cur, const char *s)
{
    size_t len = strlen(s);
    if (max - *cur >= len)
        memcpy(buf + *cur, s, len);
    *cur += len;
}

static bool str_startswith(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void fdt_prop(char *node, char *prop, uint8_t *value, size_t size)
{
    if (strcmp(prop, "reg") == 0) {
        bool is_ram = str_startswith(node, "/memory@");
        if (is_ram)
            printf("     This is RAM.\n");

        for (size_t n = 0; n < size / 16; n++) {
            uint64_t r[2];
            memcpy(r, value + n * 16, 16);
            uint64_t start = betoh64(r[0]);
            uint64_t size = betoh64(r[1]);
            printf("     MEMORY: %016llx - %016llx\n",
                   (long long)start, (long long)size);
            if (is_ram)
                page_alloc_add_ram(start, size);
        }
    }
}

static void fdt_parse(void *fdt)
{
    struct fdt_header *h = fdt;

    if (betoh32(h->magic) != 0xD00DFEED)
        panic("Invalid FDT magic.\n");
    if (betoh32(h->version) != 17)
        panic("Unknown FDT version.\n");

    char *names = (char*)fdt + betoh32(h->off_dt_strings);

    int level = 0;
    char *parents[16];
    char path[128] = "";

    uint32_t *st = (uint32_t *)((char *)fdt + betoh32(h->off_dt_struct));
    while (1) {
        uint32_t tok = betoh32(*st++);

        switch (tok) {
        case FDT_BEGIN_NODE: {
            char *name = (char *)st;
            size_t len = strlen(name) + 1;
            st += (len + 3) / 4;

            parents[level] = name;

            size_t pos = 0;
            for (size_t n = 0; n < level + 1; n++) {
                if (n > 0 || level == 0)
                    append_str(path, sizeof(path), &pos, "/");
                append_str(path, sizeof(path), &pos, parents[n]);
            }
            if (pos >= sizeof(path))
                panic("FDT node name too long.\n"); // shameful
            path[pos] = '\0';

            printf("'%s'\n", path);
            level += 1;
            break;
        }

        case FDT_PROP: {
            uint32_t len = betoh32(*st++);
            uint32_t nameoff = betoh32(*st++);
            void *value = st;
            char *name = names + nameoff;
            st += (len + 3) / 4;
            printf("  - '%s' (%u bytes)\n", name, (int)len);
            fdt_prop(path, name, value, len);
            break;
        }

        case FDT_END_NODE:
            // (Assume this cannot be followed by FDT_PROP before another
            // FDT_BEGIN_NODE, so don't update the path.)
            level -= 1;
            break;

        case FDT_NOP:
            break;

        case FDT_END:
            goto structs_end;

        default:
            panic("Unknown FDT token %d.\n", (int)tok);
        }
    }
    structs_end:;

    struct fdt_reserve_entry *resv =
        (void *)((char *)fdt + betoh32(h->off_mem_rsvmap));
    for (size_t n = 0; resv[n].address || resv[n].size; n++) {
        uint64_t start = betoh64(resv[n].address);
        uint64_t size = betoh64(resv[n].size);
        printf("RESERVED: %016llx - %016llx\n",
               (long long)start, (long long)(start + size - 1));
        page_alloc_mark(start, size, PAGE_USAGE_RESERVED);
    }

    // Maybe we want to keep the FDT.
    page_alloc_mark((uintptr_t)fdt - KERNEL_PHY_BASE,
                    betoh32(h->totalsize), PAGE_USAGE_RESERVED);

    // I have no idea? Also 2MB seems a bit much.
    printf("Adding (missing?) OpenSBI reserved memory.\n");
    page_alloc_mark(0x80000000, 0x00200000, PAGE_USAGE_RESERVED);

    printf("FDT end.\n");
}

int boot_entry(uintptr_t fdt_phys)
{
    printf("Booting with FDT at %p.\n", (void *)fdt_phys);
    if (!fdt_phys)
        panic("Bootloader provided no FDT.\n");

    fdt_parse((void *)(KERNEL_PHY_BASE + fdt_phys));

    page_alloc_mark((uintptr_t)&_start - KERNEL_PHY_BASE, &_end - &_start,
                    PAGE_USAGE_KERNEL);

    page_alloc_debug_dump();

#if 0
    void *ad1 = page_alloc(PAGE_SIZE * 3, PAGE_USAGE_GENERAL);
    void *ad2 = page_alloc(PAGE_SIZE * 4, PAGE_USAGE_GENERAL_2);
    void *ad3 = page_alloc(PAGE_SIZE, PAGE_USAGE_GENERAL_3);
    void *ad4 = page_alloc(PAGE_SIZE * 3, PAGE_USAGE_GENERAL);
    void *ad5 = page_alloc(PAGE_SIZE, PAGE_USAGE_GENERAL);
    printf("alloc %p %p %p %p %p\n", ad1, ad2, ad3, ad4, ad5);
    page_alloc_debug_dump();
    page_free(ad2, PAGE_SIZE * 4);
    page_alloc_debug_dump();
    void *ad6 = page_alloc(PAGE_SIZE * 5, PAGE_USAGE_GENERAL);
    printf("alloc %p\n", ad6);
    page_alloc_debug_dump();
    page_free(ad6, PAGE_SIZE * 5);
    page_alloc_debug_dump();
    page_free(ad5, PAGE_SIZE);
    page_free(ad1, PAGE_SIZE * 3);
    page_alloc_debug_dump();
    //page_free(ad3, PAGE_SIZE);
    //page_free(ad4, PAGE_SIZE * 3);
    page_alloc_debug_dump();

    struct slob sl;
    slob_init(&sl, 16);
    static void *ptrs[3096];
    for (size_t n = 0; n < 3096; n++)
        ptrs[n] = slob_allocz(&sl);
    void *a1 = slob_allocz(&sl);
    void *a2 = slob_allocz(&sl);
    void *a3 = slob_allocz(&sl);
    void *a4 = slob_allocz(&sl);
    printf("%p %p %p %p\n", a1, a2, a3, a4);
    slob_free(&sl, a1);
    slob_free(&sl, a4);
    a1 = slob_allocz(&sl);
    a4 = slob_allocz(&sl);
    printf("%p %p %p %p\n", a1, a2, a3, a4);
    for (size_t n = 0; n < 1000; n++)
        slob_free(&sl, ptrs[n]);

    slob_allocz(&sl);

    slob_free_unused(&sl);
    slob_allocz(&sl);
    page_alloc_debug_dump();
#endif

    // And this is why we did all this crap.
    printf("Hello world.\n");
    //memset((void *)KERNEL_PHY_BASE + 0x80000000, 0xDE, FW_JUMP_ADDR_PHY - 0x80000000);
    panic("stopping\n");
}
