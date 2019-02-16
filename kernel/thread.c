#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "page_alloc.h"
#include "thread.h"

#define KERNEL_STACK_MIN (PAGE_SIZE * 2)

void trap(void);
void trap_return(void);

static struct {
    struct thread *head, *tail;
} all_threads;

// (For simpler asm.)
static_assert(!(sizeof(struct asm_regs) & (STACK_ALIGNMENT - 1)), "");

// Represents a kernel or user mode thread. (User mode threads always imply a
// kernel thread.)
// The pointer to this struct is saved in the tp register while in kernel
// mode, and in the sscratch register while in usermode.
// Directly below this struct, the kernel stack begins (asm relies on this),
// which is also why the extra alignment is required.
struct thread {
    // Note: start of fields that are accessed from asm. Don't change them
    //       without adjusting the offsets in the asm.

    // Temporary to relieve register pressure in trap path. These registers are
    // reused by recursive trap handlers and thus used only while interrupts
    // are disabled.
    size_t scratch_sp;  // 0
    size_t scratch_tp;  // 1

    // Registers saved by syscall trap. (It saves a subset of all registers.)
    size_t syscall_ra;  // 2
    size_t syscall_sp;  // 3
    size_t syscall_gp;  // 4
    size_t syscall_tp;  // 5
    size_t syscall_pc;  // 6

    // Loaded by ASM to get the kernel environment (same for all threads; I was
    // just hesitant to duplicate the sequence for computing gp everywhere).
    void *kernel_gp;    // 7

    // End of asm fields.

    // For in-kernel thread switching.
    void *kernel_sp;
    void *kernel_pc;

    struct aspace *aspace;

    struct {
        struct thread *prev, *next;
    } all_threads;

    struct {
        struct thread *prev, *next;
    } aspace_siblings;

    // Start of the thread allocation; implies stack size and total allocation
    // size; usually points to an unreadable guard page.
    void *base;
} __attribute__((aligned(STACK_ALIGNMENT)));

// (For simpler asm.)
static_assert(!(sizeof(struct thread) & (STACK_ALIGNMENT - 1)), "");

struct thread *thread_create(struct aspace *aspace, struct asm_regs *init_regs)
{
    struct aspace *kaspace = aspace_get_kernel();
    bool is_kernel = aspace == kaspace;

    int pages =
        (KERNEL_STACK_MIN + sizeof(struct thread) + PAGE_SIZE - 1) / PAGE_SIZE;
    pages += 1; // guard page

    if ((char *)virt_alloc_end - (char *)virt_alloc_cur < pages * PAGE_SIZE)
        return NULL;

    void *base = virt_alloc_cur;
    virt_alloc_cur = (char *)virt_alloc_cur + pages * PAGE_SIZE;

    // Allocate memory for each page (except the guard page, which is simply
    // not touched, as all virt_alloc addresses should be initially unmapped).
    for (int n = 1; n < pages; n++) {
        uint64_t page = page_alloc_phy(1, PAGE_USAGE_THREAD);
        if (page == INVALID_PHY_ADDR)
            goto fail;
        if (!aspace_map(kaspace, (char *)base + n * PAGE_SIZE, page, PAGE_SIZE,
                        MMU_FLAG_R | MMU_FLAG_W))
            goto fail;
    }

    struct thread *t = (void *)((char *)base + pages * PAGE_SIZE - sizeof(*t));
    *t = (struct thread){
        .aspace = aspace,
        .base = base,
    };

    asm("mv %0, gp" : "=r" (t->kernel_gp));

    struct asm_regs *ctx = (void *)((char *)t - sizeof(*ctx));

    t->kernel_sp = ctx;
    t->kernel_pc = trap_return;

    *ctx = *init_regs;

    if (is_kernel) {
        ctx->regs[2] = (uintptr_t)t;            // sp
        ctx->regs[3] = (uintptr_t)t->kernel_gp; // gp
        ctx->regs[4] = (uintptr_t)t;            // tp
        ctx->status = (1 << 8);                 // set to SPP (kernel mode)
    }

    LL_APPEND(&all_threads, t, all_threads);
    LL_APPEND(&aspace->owners, t, aspace_siblings);

    return t;

fail:
    // TODO: deallocate allocated memory
    return NULL;
}

// Helper function for creating a kernel thread. You can't return from the
// thread. The thread function is called once the thread is first switched to.
struct thread *thread_create_kernel(void (*thread)(void *ctx), void *ctx)
{
    struct asm_regs regs = {0};
    regs.regs[10] = (uintptr_t)ctx; // a0
    regs.pc = (uintptr_t)thread;
    return thread_create(aspace_get_kernel(), &regs);
}

struct thread *thread_current(void)
{
    struct thread *t;
    asm("mv %0, tp" : "=r" (t));
    return t;
}

bool ints_disable(void)
{
    size_t r;
    asm volatile("csrrc %0, sstatus, %1"
        : "=r" (r)
        : "r" (1 << 1)
        : "memory");
    return r & (1 << 1);
}

void ints_restore(bool ints_disable_return_value)
{
    // (Always run the csrrs, just so the asm block acts as compiler barrier.)
    asm volatile("csrrs zero, sstatus, %0"
        :
        : "r" (ints_disable_return_value ? (1 << 1) : 0)
        : "memory");
}

void ints_enable(void)
{
    ints_restore(true);
}

void thread_switch_to(struct thread *t)
{
    aspace_switch_to(t->aspace);

    // Actual context switch. Note that we force the compiler to save the
    // callee-saved registers for us (although there are no advantages to do
    // this). We list _all_ registers as being clobbered, except zero,
    // sp/gp/tp, and ra. ra is used for the only "r" constraint and is clobbered
    // by being a dummy output.
    asm volatile("beqz tp, 1f\n"
                 "sd sp, (%[o_sp])(tp)\n"
                 "la a0, 2f\n"
                 "sd a0, (%[o_pc])(tp)\n"
                 "1:\n"
                 "mv tp, %[t]\n"
                 "ld sp, (%[o_sp])(tp)\n"
                 "ld a0, (%[o_pc])(tp)\n"
                 "csrw sscratch, tp\n"
                 "jr a0\n"
                 "2:\n"
        : "=r" (t) // clobbered
        : [t] "0" (t),
          [o_sp] "i" (offsetof(struct thread, kernel_sp)),
          [o_pc] "i" (offsetof(struct thread, kernel_pc))
        : "t0", "t1", "t2", "t3", "t4", "t5", "t6", // t0-t6
          "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
            "s11", // s0-s11
          "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", // a0-a7
          "memory");
}

// Unexpected exception or interrupt.
static void show_crash(struct asm_regs *ctx)
{
    printf("\n");
    printf("Oh no! This shit just crashed.\n");
    printf("\n");
    printf("SP:         %016zx\n", ctx->regs[2]);
    printf("sepc:       %016zx\n", ctx->pc);
    printf("scause:     %016zx\n", ctx->cause);
    printf("stval:      %016zx\n", ctx->tval);
    printf("sip:        %016zx\n", ctx->ip);
    printf("sstatus:    %016zx\n", ctx->status);
    printf("\n");

    uint64_t exc_code = ctx->cause & ((1ULL << 63) - 1);
    const char *cause = "?";
    if (ctx->cause & (1ULL << 63)) {
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

    const char *mode = ctx->status & (1 << 8) ? "super" : "user";
    printf("Happened in privilege level: %s\n", mode);

    printf("\n");

    panic("stop.\n");
}

void c_trap(struct asm_regs *ctx)
{
    show_crash(ctx);


    /*
    if (ctx->cause & (1ULL << 63)) {
        sbi_set_timer(read_timer_ticks() + timer_frequency * 3);
    } else {
        */
}

static void post_init_threading(void)
{
    asm volatile("csrw stvec, %[tr]\n"
        :
        : [tr] "r" (trap),
          [sc] "r" (0)
        : "memory");
}

static void idle_thread(void *ctx)
{
    post_init_threading();

    ints_enable();
    while (1)
        asm volatile("wfi");
}

void threads_init(void)
{
    struct thread *t = thread_create_kernel(idle_thread, NULL);
    if (!t)
        panic("Could not create idle thread.\n");
    thread_switch_to(t);
    panic("unreachable\n");
}
