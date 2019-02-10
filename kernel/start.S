#include "memory.h"

#define SBI_CONSOLE_PUTCHAR 1

/* Arbitrary value used to verify addressing. */
#define MAGIC 0x68104e9b

#define BOOT_STACK_SIZE (PAGE_SIZE * 4)

.section ".init.text", "ax"

.globl _start
_start:
    /* Disable interrupts. (Linux does it too, so maybe it's needed.) */
    csrw sie, zero

    /* Check the hart ID. For absurd reasons, OpenSBI makes all CPUs jump to
     * the payload entry point, and the payload entry point is forced to use
     * atomics to select a main CPU to boot. To make it simpler, require that
     * there is a CPU with mhartid==0 (this happens to work with qemu virt,
     * although the RISC-V spec says there must be at least one hart with ID 0).
     * Also, for some reason OpenSBI traps CSR accesses, and then fails to
     * emulate the mhartid register (I guess OpenSBI is quite a POS, it's the
     * least good thing in RISC-V so far), so use the value provided by OpenSBI
     * in a0, saved from _start.
     */
    bnez a0, boot_smp

    /* Make sure addressing really works. Some danger if the assembler
     * generated the wrong addressing mode. */
    la t0, magic
    lw t0, 0(t0)
    li t1, MAGIC
    li a0, 'A'
    bne t0, t1, boot_panic

    /* Make sure we were loaded at the correct address. We're still fully
     * relocatable at this point of execution, but we hardcode the address in
     * various places, so later on we might rely on being at the correct
     * address.
     * If this is not correct, adjust the address in memory.h, rebuild, and
     * be sure to update the load address used with qemu too. */
    la t0, _start
    li t1, FW_JUMP_ADDR_PHY
    li a0, 'B'
    bne t0, t1, boot_panic

    /* Setup MMU with a simple 1:1 map. */
    la t0, boot_page_dir
    /* A PTE:
     * - X / W / R / V bits set (allow all access; valid)
     * - this makes it a leaf PTE, on Sv48 establishes a 512GB "terapage"
     * - PPN is 0, i.e. points to physical address 0
     *   (assume relevant RAM is mapped within the 0..512GB region)
     */
    li t1, 0b1111
    /* Set PTE entry 0 (virtual address 0). This allows us to continue executing
     * from our current memory address, as it's not possible to atomically
     * enable the MMU and jump to the new virtual address. */
    sd t1, 0(t0)
    /* Set PTE entry for KERNEL_SPACE_BASE (normal virtual addresses). */
    li a5, MMU_PTE_INDEX(KERNEL_SPACE_BASE, 0) * 8
    add a4, t0, a5
    sd t1, 0(a4)
    /* Enable MMU by setting satp to PPN of boot_page_dir, and mode 9 (Sv48). */
    srli t1, t0, PAGE_SHIFT
    li t2, 9 << 60
    or t1, t1, t2
    csrw satp, t1

    /* Jump to the virtual address mapping (actually our real address).
     * Convoluted computation of the absolute address from a PC-relative one,
     * because I couldn't find out how to get 64 bit absolute addressing. */
    la t1, change_to_virtual
    li t2, KERNEL_PHY_BASE
    add t1, t1, t2
    mv ra, zero
    jr t1
change_to_virtual:

    /* Kill PTE entry 0. Now that we're done switching, we never want to access
     * memory via low addresses again. Makes sure we catch kernel 0 derefs. */
    sd zero, 0(t0)
    sfence.vma zero

    /* Some magic stolen from Linux. */
.option push
.option norelax
    la gp, __global_pointer$
.option pop

    la t0, crash
    csrw stvec, t0

    /* Call into C. Should never return, except on early init errors.
     * Note: a1 is saved from _start, and contains the address to the DTB (or
     *       NULL if unset). This is FW_JUMP_FDT_ADDR in OpenSBI, but no need
     *       to hardcode it. */
    la sp, boot_stack
    li t0, BOOT_STACK_SIZE
    add sp, sp, t0
    mv a0, a1
    jal boot_entry
    j boot_panic

boot_panic:
    li a7, SBI_CONSOLE_PUTCHAR
    ecall
    li a0, '!'
    ecall
    li a0, '\n'
    ecall
1:
    j 1b

boot_smp:
    /* SMP is too complicated conceptually, so let's not hurt ourselves yet. */
    wfi
    j boot_smp

    .align 3
crash:
    csrr a0, sepc
    csrr a1, scause
    csrr a2, stval
    j crash

.section ".rodata", "a"

magic:
    .word MAGIC

.section ".bss..page_aligned", "w"
.align PAGE_SHIFT

    .lcomm boot_page_dir, PAGE_SIZE
    .lcomm boot_stack, PAGE_SIZE * 8
