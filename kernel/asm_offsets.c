#include "kernel.h"
#include "thread_internal.h"

#define STRINGIFY(x) #x

#define DEFINT_NAMED(name, i) \
    asm volatile("O><|" name "|%0" : : "i" (i));

#define DEFINT(name) \
    DEFINT_NAMED(# name, name)

#define OFFSET(type, field) \
    DEFINT_NAMED(STRINGIFY(type) "_" STRINGIFY(field), offsetof(type, field))

#define SIZE(type) \
    DEFINT_NAMED(STRINGIFY(type) "_size", sizeof(type))

void unused(void) {
    SIZE(struct asm_regs)

    OFFSET(struct asm_regs, regs)
    OFFSET(struct asm_regs, pc)
    OFFSET(struct asm_regs, status)
    OFFSET(struct asm_regs, cause)
    OFFSET(struct asm_regs, tval)
    OFFSET(struct asm_regs, ip)

    OFFSET(struct thread, scratch_sp)
    OFFSET(struct thread, scratch_tp)
    OFFSET(struct thread, kernel_sp)
    OFFSET(struct thread, kernel_pc)
    OFFSET(struct thread, syscall_ra)
    OFFSET(struct thread, syscall_sp)
    OFFSET(struct thread, syscall_gp)
    OFFSET(struct thread, syscall_tp)
    OFFSET(struct thread, syscall_pc)
    OFFSET(struct thread, syscall_sstatus)
    OFFSET(struct thread, syscall_cs)
    OFFSET(struct thread, trap_sp);
    OFFSET(struct thread, trap_pc);

    DEFINT(SYSCALL_COUNT)
}
