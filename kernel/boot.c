#include <endian.h>
#include <elf.h>

#include "handle.h"
#include "kernel.h"
#include "kmalloc.h"
#include "memory.h"
#include "mmu.h"
#include "page_alloc.h"
#include "sbi.h"
#include "slob.h"
#include "thread.h"
#include "time.h"
#include "virtual_memory.h"

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

// Virtual memory area that can be used for arbitrary kernel mappings.
// Set it to something... arbitrary, hope it doesn't collide.
void *virt_alloc_cur = (void *)VIRT_ALLOC_BASE;
void *virt_alloc_end = (void *)-(uintptr_t)(PAGE_SIZE);

static uint64_t initrd_phys_start, initrd_phys_end;

static void continue_boot(void);

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

    if (strcmp(node, "/cpus") == 0 && strcmp(prop, "timebase-frequency") == 0)
        timer_frequency = betoh32(*(uint32_t *)value);

    if (strcmp(node, "/chosen") == 0) {
        if (strcmp(prop, "bootargs") == 0)
            printf("     '%s'\n", (char *)value);

        // How to do many things wrong with something extremely simple:
        // - make separate properties
        // - make them 32 bit only
        // - don't use the standard reg property
        if (strcmp(prop, "linux,initrd-start") == 0)
            initrd_phys_start = betoh32(*(uint32_t *)value);
        if (strcmp(prop, "linux,initrd-end") == 0)
            initrd_phys_end = betoh32(*(uint32_t *)value);
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
            if (level >= ARRAY_ELEMS(parents))
                panic("FDT nesting too deep.\n");
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

    if (initrd_phys_start != initrd_phys_end) {
        page_alloc_mark(initrd_phys_start, initrd_phys_end - initrd_phys_start,
                        PAGE_USAGE_RESERVED);
    }

    printf("FDT end.\n");
}

struct mem_file {
    struct vm_object_ref *vm;
    void *start;
    size_t size;
};

static int mem_file_read_page(void *ud, uint64_t offset)
{
    struct mem_file *priv = ud;

    assert(offset < priv->size);

    uint64_t phys = vm_objref_page_create_phys(priv->vm, offset);
    if (phys == INVALID_PHY_ADDR)
        return -1;

    void *addr = page_phys_to_virt(phys);
    assert(addr);

    size_t size = MIN(priv->size - offset, PAGE_SIZE);
    printf("page in %ld %zd -> %lx\n", (long)offset, size, (long)phys);

    memcpy(addr, (char *)priv->start + offset, size);
    memset((char *)addr + size, 0, PAGE_SIZE - size);
    return 0;
}

static const struct vm_object_ops mem_file_ops = {
    .read_page = mem_file_read_page,
};

static struct vm_object_ref *create_mem_file(void *start, size_t size)
{
    struct mem_file *priv = mallocz(sizeof(struct mem_file));
    if (!priv)
        return NULL;

    *priv = (struct mem_file){
        .start = start,
        .size = size,
        .vm = vm_objref_create(&mem_file_ops, priv),
    };

    if (!priv->vm) {
        free(priv);
        return NULL;
    }

    vm_objref_set_size(priv->vm, size);

    return priv->vm;
}

// Load a userspace executable into the given address space.
// Uses the VM system, and *elf must remain allocated.
static void load_elf(void *elf, size_t elf_size, struct vm_aspace *as,
                     uintptr_t *out_entry)
{
    struct vm_object_ref *file = create_mem_file(elf, elf_size);
    if (!file)
        panic("Failed to allocate VM object.\n");

    if ((uintptr_t)elf & 7)
        panic("ELF loader input not aligned.\n");

    if (elf_size < sizeof(Elf64_Ehdr))
        panic("ELF file too small.\n");

    Elf64_Ehdr *hdr = elf;

    static const uint8_t elf_ident[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
                                        ELFCLASS64, ELFDATA2LSB, EV_CURRENT};
    if (memcmp(hdr->e_ident, elf_ident, sizeof(elf_ident)) != 0)
        panic("Invalid/unsupported ELF header, endian, or bit size.\n");

    if (hdr->e_type != ET_EXEC)
        panic("Not an executable (static) ELF file.\n");

    if (hdr->e_machine != EM_RISCV)
        panic("ELF file is not RISC-V.\n");

    if (!hdr->e_phoff)
        panic("ELF file has no program headers.\n");

    if (hdr->e_phoff + hdr->e_phnum * (uint64_t)hdr->e_phentsize > elf_size ||
        hdr->e_phentsize < sizeof(Elf64_Phdr))
        panic("ELF program headers out of bounds or invalid.\n");

    for (size_t n = 0; n < hdr->e_phnum; n++) {
        Elf64_Phdr *phdr =
            (void *)((char *)elf + hdr->e_phoff + n * hdr->e_phentsize);

        if (phdr->p_type != PT_LOAD)
            continue;

        if ((phdr->p_offset % PAGE_SIZE) != (phdr->p_vaddr % PAGE_SIZE))
            panic("ELF program header offsets not congruent.\n");

        int map_flags = ((phdr->p_flags & 1) ? KERN_MAP_PERM_X : 0) |
                        ((phdr->p_flags & 2) ? KERN_MAP_PERM_W : 0) |
                        ((phdr->p_flags & 4) ? KERN_MAP_PERM_R : 0) |
                        KERN_MAP_FORK_COPY | KERN_MAP_OVERWRITE;

        if (phdr->p_offset > elf_size ||
            elf_size < phdr->p_offset + phdr->p_filesz)
        {
            panic("ELF PHDR file data outside of file.\n");
        }
        uintptr_t offs_end = phdr->p_offset + phdr->p_filesz;
        uintptr_t offs_a = phdr->p_offset & ~(uintptr_t)(PAGE_SIZE - 1);

        uintptr_t vaddr_a = phdr->p_vaddr & ~(uintptr_t)(PAGE_SIZE - 1);
        uintptr_t vaddr_end = phdr->p_vaddr + phdr->p_memsz;
        uintptr_t vaddr_end_a = (vaddr_end + PAGE_SIZE - 1) &
                                ~(uintptr_t)(PAGE_SIZE - 1);

        if (vaddr_end < phdr->p_vaddr)
            panic("ELF PHDR virtual address overflow.\n");

        // Mapped file data (starting at offs_a/vaddr_a).
        size_t file_size =
            (offs_end - offs_a + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1);
        // Mapped anonymous memory (starting at vaddr_a+file_size).
        size_t anon_size = vaddr_end_a - (vaddr_a + file_size);

        // Number of bytes to before the end of the file mapped region (to zero
        // out partial BSS). If 0, clear nothing.
        size_t clear_offs = phdr->p_memsz > phdr->p_filesz ?
                            (offs_end & (PAGE_SIZE - 1)) : 0;

        if (file_size) {
            void *a = vm_mmap(as, (void *)vaddr_a, file_size,
                              map_flags | KERN_MAP_COW, file, offs_a);
            if (KERN_MMAP_FAILED(a))
                panic("Could not map ELF file.\n");

            if (clear_offs) {
                uintptr_t clear_addr = vaddr_a + file_size - PAGE_SIZE;
                uint64_t phys = vm_aspace_get_phys(as, (void *)clear_addr,
                                                   KERN_MAP_PERM_W);
                if (phys == INVALID_PHY_ADDR)
                    panic("Could not touch partial .bss page.\n");
                a = page_phys_to_virt(phys);
                assert(a);
                memset((char *)a + clear_offs, 0, PAGE_SIZE - clear_offs);
            }
        }

        if (anon_size) {
            void *a = vm_mmap(as, (void *)(vaddr_a + file_size), anon_size,
                              map_flags, NULL, 0);
            if (KERN_MMAP_FAILED(a))
                panic("Could not map ELF .bss.\n");
        }
    }

    *out_entry = hdr->e_entry;
}

static void map_kernel(void *addr, size_t size, int flags)
{
    uint64_t phys = (uintptr_t)addr - KERNEL_PHY_BASE;

    // Extend address range to page boundaries.
    size += phys & (PAGE_SIZE - 1);
    phys &= ~(uint64_t)(PAGE_SIZE - 1);
    addr = (void *)((uintptr_t)addr & ~(uintptr_t)(PAGE_SIZE - 1));
    size = (size + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

    for (size_t n = 0; n < size / PAGE_SIZE; n++) {
        bool r = mmu_map(mmu_get_kernel(), addr, phys, PAGE_SIZE, flags);
        if (!r)
            panic("Could not establish kernel mapping.\n");
        addr = (char *)addr + PAGE_SIZE;
        phys += PAGE_SIZE;
    }
}

// The microkernel who parsed tar in the kernel.
static void initrd_tar_next(size_t *pos, char **filename,
                            void **data, size_t *size)
{
    *filename = NULL;
    *data = NULL;
    *size = 0;

    size_t left = initrd_phys_end - initrd_phys_start - *pos;
    if (left == 0)
        return;

    char *hdr = page_phys_to_virt(initrd_phys_start + *pos);
    assert(hdr);

    if (left < 512)
        panic("Partial tar header.\n");

    // Check for all-0 termination block.
    char m = 0;
    for (size_t n = 0; n < 512; n++)
        m |= hdr[n];
    if (!m)
        return;

    if (memcmp(&hdr[257], "ustar\0", 6) != 0)
        panic("Invalid tar header signature.\n");

    // (Valid in tar, but we rely on 0 termination.)
    if (hdr[99])
        panic("Filename too long.\n");

    uint64_t esize = 0;
    for (size_t n = 0; n < 12; n++) {
        char c = hdr[124 + n];
        if (!c)
            break;
        if (!(c >= '0' && c <= '7'))
            panic("Invalid tar header '%d'.\n", c);
        esize = (esize << 3) + (c - '0');
    }

    if (esize > left - 512)
        panic("Invalid tar entry size.\n");

    *pos += 512 + esize;
    *filename = &hdr[0];
    *data = hdr + 512;
    *size = esize;
}

int boot_entry(uintptr_t fdt_phys)
{
    size_t sstatus;
    asm volatile("csrr %0, sstatus" : "=r" (sstatus));
    printf("Boot sstatus: 0x%zx\n", sstatus);

    asm volatile("csrw sstatus, %0" : : "r" ((2ULL << 32) | 0x80000));
    asm volatile("csrr %0, sstatus" : "=r" (sstatus));
    printf("New sstatus: 0x%zx\n", sstatus);

    printf("Booting with FDT at %p.\n", (void *)fdt_phys);
    if (!fdt_phys)
        panic("Bootloader provided no FDT.\n");

    fdt_parse((void *)(KERNEL_PHY_BASE + fdt_phys));

    printf("Timer frequency: %ld Hz\n", (long)timer_frequency);
    if (!timer_frequency)
        panic("Timer frequency not found in FDT.\n");

    time_init(timer_frequency);

    page_alloc_mark((uintptr_t)&_start - KERNEL_PHY_BASE, &_end - &_start,
                    PAGE_USAGE_KERNEL);

    printf("initrd: %lx-%lx\n", (long)initrd_phys_start, (long)initrd_phys_end);
    if (initrd_phys_start >= initrd_phys_end)
        panic("No initrd set in FDT.\n");

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

    mmu_init();

    // Remap used parts of the virtual address space.

    for (int index = 0; ; index++) {
        uint64_t addr, size;
        page_alloc_get_ram(index, &addr, &size);
        if (!size)
            break;
        void *virt = page_phys_to_virt(addr);
        assert(virt);
        map_kernel(virt, size, MMU_FLAG_R | MMU_FLAG_W);
    }

    // Mapping the same page multiple times fully overwrites the previous
    // permissions, so be careful with the order and the linker script.
    map_kernel(&_stext,     &_etext - &_stext,      MMU_FLAG_R | MMU_FLAG_X);
    map_kernel(&_sdata,     &_edata - &_sdata,      MMU_FLAG_R | MMU_FLAG_W);
    map_kernel(&_sbss,      &_ebss - &_sbss,        MMU_FLAG_R | MMU_FLAG_W);
    map_kernel(&_srodata,   &_erodata - &_srodata,  MMU_FLAG_R);

    page_alloc_debug_dump();

    // Switch away from the boot page table.
    mmu_switch_to(mmu_get_kernel());

    // Switch to a proper kernel thread, which calls the given function to
    // continue booting. This also switches away from the boot stack, and sets
    // up a proper crash handler.
    threads_init(continue_boot);

    panic("unreachable\n");
}

static void continue_boot(void)
{
    syscalls_self_check();

    printf("initrd contents:\n");
    size_t initrd_pos = 0;
    void *root_elf = NULL;
    size_t root_elf_size = 0;
    while (1) {
        char *filename;
        void *data;
        size_t size;
        initrd_tar_next(&initrd_pos, &filename, &data, &size);
        if (!filename)
            break;

        printf("  - '%s' (%zd bytes)\n", filename, size);

        if (strcmp(filename, "rootprocess") == 0) {
            root_elf = data;
            root_elf_size = size;
        }
    }

    if (!root_elf)
        panic("initrd rootprocess entry not found.\n");

    struct vm_aspace *as = vm_aspace_create();
    if (!as)
        panic("Could not allocate user addressspace.\n");

    mmu_switch_to(vm_aspace_get_mmu(as));
    if (!handle_table_create(vm_aspace_get_mmu(as)))
        panic("Failed to create user handle table.\n");

    uintptr_t entrypoint;
    load_elf(root_elf, root_elf_size, as, &entrypoint);

    // Create a stack at the end of the user address space.
    size_t user_stack_size = PAGE_SIZE * 16;
    uintptr_t user_stack =
        (MMU_ADDRESS_LOWER_MAX & ~(uintptr_t)(PAGE_SIZE - 1)) -
        PAGE_SIZE * 1024 - user_stack_size;
    void *r = vm_mmap(as, (void *)user_stack, user_stack_size,
                      KERN_MAP_FORK_COPY | KERN_MAP_PERM_W | KERN_MAP_PERM_R,
                      NULL, 0);
    if (KERN_MMAP_FAILED(r))
        panic("Failed to map user stack.\n");

    page_alloc_debug_dump();

    asm volatile("csrw sie, %0" : : "r"((1 << 9) | (1 << 5) | (1 << 1)));

    // Make sure timer IRQ fires at least once.
    time_set_next_event(1);

    struct thread *ut = thread_create();
    if (!ut)
        panic("Failed to create user thread.\n");

    struct handle h = {
        .type = HANDLE_TYPE_THREAD,
        .u = {
            .thread = ut,
        },
    };
    int64_t t_h = handle_add_or_free_on(vm_aspace_get_mmu(as), &h);
    if (!KERN_IS_HANDLE_VALID(t_h))
        panic("Failed to create thread handle.\n");

    struct asm_regs regs = {0};
    regs.status = 1 << 1;
    regs.regs[2] = user_stack + user_stack_size;
    regs.regs[10] = t_h;
    regs.pc = entrypoint;
    thread_set_user_context(ut, &regs);

    thread_set_aspace(ut, as);

    printf("user thread: %p\n", ut);
    printf("current thread: %p\n", thread_current());
}
