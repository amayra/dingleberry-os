#include <endian.h>

#include "kernel.h"
#include "memory.h"
#include "mmu.h"
#include "opensbi.h"
#include "page_alloc.h"
#include "slob.h"

extern char _start;
extern char _end;

extern char _stext;
extern char _etext;
extern char _srodata;
extern char _erodata;
extern char _sdata;
extern char _edata;
extern char _sbss;
extern char _ebss;

static uint64_t timer_frequency;

uint64_t read_timer_ticks(void)
{
    uint64_t r;
    asm("rdtime %0" : "=r" (r));
    return r;
}

void trap(void);

struct trap_info {
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t sip;

    // General purpose registers, minus x0. (regs[n] = x(n + 1).)
    uint64_t regs[31];
};

static struct trap_info trap_info;

void c_trap(void)
{
    // Doesn't need to be strictly part of the saved state. It won't get
    // clobbered until we enable interrupts or so.
    uint64_t sstatus;
    asm volatile("csrr %0, sstatus" : "=r" (sstatus));

    printf("\n");
    printf("Oh no! This shit just crashed.\n");
    printf("\n");
    printf("SP:         %016"PRIx64"\n", trap_info.regs[1]);
    printf("sepc:       %016"PRIx64"\n", trap_info.sepc);
    printf("scause:     %016"PRIx64"\n", trap_info.scause);
    printf("stval:      %016"PRIx64"\n", trap_info.stval);
    printf("sip:        %016"PRIx64"\n", trap_info.sip);
    printf("sstatus:    %016"PRIx64"\n", sstatus);
    printf("\n");

    uint64_t exc_code = trap_info.scause & ((1ULL << 63) - 1);
    const char *cause = "?";
    if (trap_info.scause & (1ULL << 63)) {
        switch (exc_code) {
        case 0: cause = "user software IRQ"; break;
        case 1: cause = "super software IRQ"; break;
        case 4: cause = "user timer IRQ"; break;
        case 5: cause = "super timer IRQ"; break;
        case 8: cause = "user external IRQ"; break;
        case 9: cause = "super external IRQ"; break;
        }
    } else {
        switch (exc_code) {
        case 0: cause = "instruction misaligned"; break;
        case 1: cause = "instruction access"; break;
        case 2: cause = "illegal instruction"; break;
        case 3: cause = "breakpoint"; break;
        case 4: cause = "load misaligned"; break;
        case 5: cause = "load access"; break;
        case 6: cause = "store/AMO misaligned"; break;
        case 7: cause = "load/AMO misaligned"; break;
        case 8: cause = "user ecall"; break;
        case 9: cause = "super ecall"; break;
        case 12: cause = "instruction page fault"; break;
        case 13: cause = "load page fault"; break;
        case 15: cause = "store/AMO page fault"; break;
        }
    }
    printf("Cause: %s\n", cause);

    const char *mode = sstatus & (1 << 8) ? "super" : "user";
    printf("Happened in privilege level: %s\n", mode);

    printf("\n");
    panic("stop.\n");
}

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

    if (strcmp(prop, "compatible") == 0) {
        while (size) {
            char *c = (char *)value;
            printf("     '%s'\n", c);
            size_t len = strlen(c) + 1;
            assert(len <= size);
            value += len;
            size -= len;
        }
    }

    if (strcmp(prop, "model") == 0) {
        printf("     '%s'\n", (char *)value);
    }

    if (strcmp(node, "/cpus") == 0 && strcmp(prop, "timebase-frequency") == 0) {
        assert(size >= 4); // we can trust devicetree, right?
        timer_frequency = betoh32(*(uint32_t *)value);
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

static void map_kernel(void *addr, size_t size, int flags)
{
    uint64_t phys = (uintptr_t)addr - KERNEL_PHY_BASE;

    // Extent address range to page boundaries.
    size += phys & (PAGE_SIZE - 1);
    phys &= ~(uint64_t)(PAGE_SIZE - 1);
    addr = (void *)((uintptr_t)addr & ~(uintptr_t)(PAGE_SIZE - 1));
    size = (size + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

    bool r = aspace_map(aspace_get_kernel(), addr, phys, size, flags);
    if (!r)
        panic("Could not establish kernel mapping.\n");
}

int boot_entry(uintptr_t fdt_phys)
{
    printf("Booting with FDT at %p.\n", (void *)fdt_phys);
    if (!fdt_phys)
        panic("Bootloader provided no FDT.\n");

    fdt_parse((void *)(KERNEL_PHY_BASE + fdt_phys));

    printf("Timer frequency: %ld Hz\n", (long)timer_frequency);
    if (!timer_frequency)
        panic("Timer frequency not found in FDT.\n");

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

    aspace_init();

    // Remap used parts of the virtual address space.

    for (int index = 0; ; index++) {
        uint64_t addr, size;
        page_alloc_get_ram(index, &addr, &size);
        if (!size)
            break;
        void *virt = page_phys_to_virt(addr);
        assert(virt);
        bool r = aspace_map(aspace_get_kernel(), virt, addr, size,
                            MMU_FLAG_R | MMU_FLAG_W | MMU_FLAG_X);
        if (!r)
            panic("Could create virtual mapping for entire RAM.\n");
    }

    // Mapping the same page multiple time fully overwrites the previous
    // permissions, so be careful of the order and the linker script.
    map_kernel(&_stext,     &_etext - &_stext,      MMU_FLAG_R | MMU_FLAG_X);
    map_kernel(&_sdata,     &_edata - &_sdata,      MMU_FLAG_R | MMU_FLAG_W);
    map_kernel(&_sbss,      &_ebss - &_sbss,        MMU_FLAG_R | MMU_FLAG_W);
    map_kernel(&_srodata,   &_erodata - &_srodata,  MMU_FLAG_R);

    // Switch away from the boot page table.
    aspace_switch_to(aspace_get_kernel());

    page_alloc_debug_dump();

    uint64_t useraddr = page_alloc_phy(1, PAGE_USAGE_GENERAL);
    assert(useraddr != INVALID_PHY_ADDR);
    extern char userspace_template;
    void *uservirt_kernel = page_phys_to_virt(useraddr);
    memcpy(uservirt_kernel, &userspace_template, PAGE_SIZE);
    struct aspace *user_aspace = aspace_alloc();
    assert(user_aspace);
    void *uservirt = (void *)(uintptr_t)0x10000;
    bool r = aspace_map(user_aspace, uservirt, useraddr, PAGE_SIZE,
                        MMU_FLAG_R | MMU_FLAG_X);
    assert(r);
    aspace_switch_to(user_aspace);

    asm volatile("csrw sepc, %0" : : "r" (uservirt));

    asm volatile("csrw sscratch, %[sc]\n"
                 "csrw stvec, %[tr]\n"
                 "csrrs zero, sstatus, %[sie]\n"
        :
        : [tr] "r" (trap),
          [sc] "r" (&trap_info),
          [sie] "r" ((1 << 1) | (1 << 0))
        : "memory");

    // And this is why we did all this crap.
    printf("Hello world.\n");

    // cause timer irq in 5 seconds
    sbi_set_timer(read_timer_ticks() + timer_frequency * 3);

    //*(volatile int *)0xDEAD = 456; // fuck this world
    //*(volatile int *)0xDEAD;
    //asm volatile("jr %0" : : "r" (0xDEAC));
    //asm volatile("ebreak");
    //asm volatile("ecall"); randomly calls into firmware
    asm volatile("csrw sie, %0" : : "r"((1 << 9) | (1 << 5) | (1 << 1)));
    asm volatile("sret"); // return to userspace

    while(1)
        asm volatile("wfi");
}
