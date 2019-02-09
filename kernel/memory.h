#pragma once

// So nobody could be bothered to add support for ULL number suffixes to
// GNU ld. Assholes.
#ifdef IN_LINKERSCRIPT
#define ULL(x) x
#else
#define ULL(x) x ## ULL
#endif

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1 << PAGE_SHIFT)

// Usable virtual address bits.
// We're hardcoded to Sv48.
#define MMU_ADDRESS_BITS        48

// The last valid address bit must be repeated in the unused higher address bits
// (like sign extension). This is the first valid upper address.
#define MMU_ADDRESS_UPPER       \
    (ULL(0xFFFFFFFFFFFFFFFF) & ~((ULL(1) << (MMU_ADDRESS_BITS - 1)) - 1))

// Sv48.
#define MMU_NUM_LEVELS          4
#define MMU_PTE_BITS            9

// Get the PTE index for the given address at the given level. Level 0 is the
// top-level, MMU_NUM_LEVELS-1 the deepest level.
#define MMU_PTE_INDEX(addr, level) \
    (((addr) >> ((MMU_NUM_LEVELS - (level) - 1) * MMU_PTE_BITS + PAGE_SHIFT)) & \
     ((1 << MMU_PTE_BITS) - 1))

// Sv48 "terapage"
#define PAGE_SIZE_TERA          (1ULL << 39)

#define L1_CACHE_SHIFT          6
#define L1_CACHE_BYTES          (1 << L1_CACHE_SHIFT)

// Start of the kernel space address space. We follow the traditional way of
// splitting the address space into a low user space and a high kernel space
// half (thus kernel space goes until 0xF...F).
#define KERNEL_SPACE_BASE       MMU_ADDRESS_UPPER

// We establish a 1:1 map of physical memory to virtual, with a base offset. The
// entire kernel virtual address space is mapped to the start of physical
// memory. You access physical address x with a (KERNEL_PHY_BASE + x) virtual
// memory access.
#define KERNEL_PHY_BASE         KERNEL_SPACE_BASE

// Size of kernel physical address space mapped at boot.
// This uses a single "terapage" PTE.
#define BOOT_PHY_MAP_SIZE       PAGE_SIZE_TERA

// OpenSBI's FW_JUMP_ADDR (for qemu virt platform). When running qemu, we use
// fw_jump.elf with this address, and load the kernel image to this address.
// Of course, this is located in RAM (and we rely on being able to write to it).
#define FW_JUMP_ADDR_PHY        0x80200000

// Virtual address where the kernel is located. We hardcode this to the virtual
// address where, due to the 1:1 mapping, the kernel will end up once the MMU
// is enabled.
// (It would not be that much effort to make it fully relocatable, but it'd be
// more complex and more fragile anyway, so why bother?)
#define LOAD_OFFSET             (KERNEL_PHY_BASE + FW_JUMP_ADDR_PHY)
