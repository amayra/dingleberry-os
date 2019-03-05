#include "thread_internal.h"

#define STRINGIFY(x) #x

#define OFFSET(type, field) \
    asm("O><|" STRINGIFY(type) "|" STRINGIFY(field) "|" "%0" \
        : : "i" (offsetof(type, field)));

#define SIZE(type) \
    asm("O><|" STRINGIFY(type) "|size|" "%0" : : "i" (sizeof(type)));

void unused(void) {
    SIZE(struct asm_regs)

    OFFSET(struct asm_regs, regs);
    OFFSET(struct asm_regs, pc);
    OFFSET(struct asm_regs, status);
    OFFSET(struct asm_regs, cause);
    OFFSET(struct asm_regs, tval);
    OFFSET(struct asm_regs, ip);

    OFFSET(struct thread, scratch_sp)
    OFFSET(struct thread, scratch_tp);
    OFFSET(struct thread, syscall_ra);
    OFFSET(struct thread, syscall_sp);
    OFFSET(struct thread, syscall_gp);
    OFFSET(struct thread, syscall_tp);
    OFFSET(struct thread, syscall_pc);
    OFFSET(struct thread, syscall_cs);
}
