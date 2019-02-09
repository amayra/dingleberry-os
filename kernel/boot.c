#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"

#define panic(...) do {     \
    printf(__VA_ARGS__);    \
    abort();                \
} while (0)

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
    if (str_startswith(node, "/memory@") && strcmp(prop, "reg") == 0) {
        for (size_t n = 0; n < size / 16; n++) {
            uint64_t r[2];
            memcpy(r, value + n * 16, 16);
            printf("     MEMORY: %016llx - %016llx\n",
                   (long long)r[0], (long long)(r[0] + r[1] - 1));
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
        printf("RESERVED: %016llx - %016llx\n",
               (long long)resv[n].address,
               (long long)(resv[n].address + resv[n].size - 1));
    }

    printf("FDT end.\n");
}

int boot_entry(uintptr_t fdt_phys)
{
    printf("Booting with FDT at %p.\n", (void *)fdt_phys);
    if (!fdt_phys)
        panic("Bootloader provided no FDT.\n");

    fdt_parse((void *)(KERNEL_PHY_BASE + fdt_phys));

    // And this is why we did all this crap.
    printf("Hello world.\n");
    abort();
}
