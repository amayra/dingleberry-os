#include "memory.h"

#define TRAP_STACK_SIZE PAGE_SIZE

.section ".text", "ax"

/*
    struct trap_info {
        uint64_t sepc;      // 0
        uint64_t scause;    // 1
        uint64_t stval;     // 2
        uint64_t sip;       // 3

        // 4
        // General purpose registers, minus x0. (regs[n] = x(n + 1).)
        uint64_t regs[31];
    };
*/

.globl trap
trap:
    csrrw t0, sscratch, t0

    /* Save general purpose registers here. */
    sd t1, ((4 + 4) * 8)(t0)    /* regs[5] = x6 = t1 */

    /* Get and save the original t0. */
    csrr t1, sscratch
    sd t1, ((4 + 4) * 8)(t0)    /* regs[4] = x5 = t0 */

    sd x1, ((4 + 0) * 8)(t0)    /* regs[0] = x1 = ra */
    sd x2, ((4 + 1) * 8)(t0)    /* regs[1] = x2 = sp */
    /* (shittons of registers omitted) */

    sd x31, ((4 + 30) * 8)(t0)  /* regs[30] = x31 = t6 */

    csrr t1, sepc
    sd t1, (0 * 8)(t0)

    csrr t1, scause
    sd t1, (1 * 8)(t0)

    csrr t1, stval
    sd t1, (2 * 8)(t0)

    csrr t1, sip
    sd t1, (3 * 8)(t0)

    /* On user entry, we'd switch to a kernel stack here.
     * On kernel IRQs, we'd probably want to keep the current stack (i.e. use
     * saved sp register.
     * We should always set a separate trap stack on actual kernel "crashes",
     * to catch un-nice things like corrupted stacks. */
    la sp, trap_stack
    li t0, TRAP_STACK_SIZE
    add sp, sp, t0
    j c_trap

    /* Notes for returning:
     * - obviously set sscratch and sepc
     * - not so obviously set sstatus SPP bit to correct value
     * - set SIE/UIE bits
     * - and SPIE??? (make sure ints are disable on nested supervisor traps)
     */
.balign 4096
.globl userspace_template
userspace_template:
    wfi
    j userspace_template
.balign 4096

.section ".bss..page_aligned", "w"
.align PAGE_SHIFT

    .lcomm trap_stack, PAGE_SIZE
