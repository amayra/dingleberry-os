#include "arch.h"
#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "mmu_internal.h"
#include "opensbi.h"
#include "page_alloc.h"
#include "thread.h"
#include "virtual_memory.h"

#define KERNEL_STACK_MIN (PAGE_SIZE / 2)

void trap(void);
void trap_return(void);

static struct {
    struct thread *head, *tail;
} all_threads;

// per CPU
bool (*g_filter_kernel_pagefault)(struct asm_regs *regs, void *memory_addr);

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
    // reused by recursive trap handlers and thus valid only while interrupts
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

    struct vm_aspace *aspace;
    struct mmu *mmu;

    struct {
        struct thread *prev, *next;
    } all_threads;

    struct {
        struct thread *prev, *next;
    } mmu_siblings;

    // Start of the thread allocation; implies stack size and total allocation
    // size; usually points to an unreadable guard page.
    void *base;

    // Unused. Just checking how much damn space this eats up. We try to get by
    // with 1 4K page per thread (including kernel stack), so if this gets too
    // much, move to a separate slab allocation. (Same for V extensions.)
    struct fp_regs fp_state;
} __attribute__((aligned(STACK_ALIGNMENT)));

// (For simpler asm.)
static_assert(!(sizeof(struct asm_regs) & (STACK_ALIGNMENT - 1)), "");
static_assert(!(sizeof(struct thread) & (STACK_ALIGNMENT - 1)), "");

struct thread *thread_create(struct vm_aspace *aspace, struct asm_regs *init_regs)
{
    struct mmu *kmmu = mmu_get_kernel();
    struct mmu *mmu = aspace ? vm_aspace_get_mmu(aspace) : kmmu;
    bool is_kernel = !aspace;

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
        if (!mmu_map(kmmu, (char *)base + n * PAGE_SIZE, page, PAGE_SIZE,
                     MMU_FLAG_R | MMU_FLAG_W))
            goto fail;
    }

    struct thread *t = (void *)((char *)base + pages * PAGE_SIZE - sizeof(*t));
    *t = (struct thread){
        .aspace = aspace,
        .mmu = mmu,
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
        ctx->status = (1 << 8);                 // set SPP (kernel mode)
    }
    ctx->status |= (2ULL << 32) | 0x80000;

    LL_APPEND(&all_threads, t, all_threads);
    LL_APPEND(&mmu->owners, t, mmu_siblings);

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
    return thread_create(NULL, &regs);
}

struct vm_aspace *thread_get_aspace(struct thread *t)
{
    return t->aspace;
}

struct thread *thread_current(void)
{
    struct thread *t;
    asm("mv %0, tp" : "=r" (t));
    return t;
}

void thread_reschedule(void)
{
    struct thread *cur = thread_current();
    struct thread *next = cur->all_threads.next;
    if (!next)
        next = all_threads.head;

    thread_switch_to(next);
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
    mmu_switch_to(t->mmu);

    // Set time slice for thread t. We don't actually know at which places
    // we return from userspace (different entrypoints like syscalls, IRQ, and
    // newly created threads), so do it here.
    // for now cause timer irq in 1 second
    sbi_set_timer(read_timer_ticks() + timer_frequency * 1);

    // Actual context switch.
    // Shitty detail about saving registers: we force the compiler to save the
    // callee-saved registers for us (although there are no advantages to do
    // this). We list _all_ registers as being clobbered, except zero,
    // sp/gp/tp, and ra. ra is used for the only "r" constraint and is clobbered
    // by being a dummy output.
    asm volatile("sd sp, (%[o_sp])(tp)\n"
                 "la a0, 1f\n"
                 "sd a0, (%[o_pc])(tp)\n"
                 "mv tp, %[t]\n"
                 "ld sp, (%[o_sp])(tp)\n"
                 "ld a0, (%[o_pc])(tp)\n"
                 "csrw sscratch, tp\n"
                 "jr a0\n"
                 "1:\n"
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

static void show_regs(struct asm_regs *ctx)
{
    printf("\n");
    printf("SP:         %016zx\n", ctx->regs[2]);
    printf("sepc:       %016zx\n", ctx->pc);
    printf("scause:     %016zx\n", ctx->cause);
    printf("stval:      %016zx\n", ctx->tval);
    printf("sip:        %016zx\n", ctx->ip);
    printf("sstatus:    %016zx\n", ctx->status);
    printf("\n");

    static const char regnames[32][5] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4",
        "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
    };

    for (size_t n = 0; n < 32; n += 2) {
        if (!ctx->regs[n + 0] && !ctx->regs[n + 1])
            continue;
        printf("%-4s   %016zx  ", regnames[n + 0], ctx->regs[n + 0]);
        printf("%-4s   %016zx\n", regnames[n + 1], ctx->regs[n + 1]);
    }

    printf("\n");
}

// Unexpected exception or interrupt.
static void show_crash(struct asm_regs *ctx)
{
    printf("\n");
    printf("Oh no! This shit just crashed.\n");

    show_regs(ctx);

    printf("Thread: %p\n", thread_current());
    printf("Context: %p\n", ctx);

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
        case 6: cause = "store misaligned"; break;
        case 7: cause = "load misaligned"; break;
        case 8: cause = "user ecall"; break;
        case 9: cause = "super ecall"; break;
        case 12: cause = "instruction page fault"; break;
        case 13: cause = "load page fault"; break;
        case 15: cause = "store page fault"; break;
        }
    }
    printf("Cause: %s\n", cause);

    const char *mode = ctx->status & (1 << 8) ? "super" : "user";
    printf("Happened in privilege level: %s\n", mode);
    printf("Current kernel stack: %p\n", &(char){0});
    asm volatile("csrrs zero, sstatus, %0" : : "r" (SSTATUS_SUM) : "memory");

    printf("\n");
}

void c_trap(struct asm_regs *ctx)
{
    if (ctx->cause == ((1ULL << 63) | 5)) {
        printf("timer IRQ\n");
        thread_reschedule();
    } else {
        // The RISC-V spec. doesn't define what most of the exception codes
        // actually mean (lol?). The intention is to catch all page faults that
        // are caused by missing mmu PTE flags.
        if (ctx->cause == 13 || ctx->cause == 15 || ctx->cause == 12) {
            void *fault_addr = (void *)(uintptr_t)ctx->tval;
            if (g_filter_kernel_pagefault && ctx->cause != 12) {
                if (g_filter_kernel_pagefault(ctx, fault_addr)) {
                    show_crash(ctx);
                    printf("(filterted)\n");
                    return;
                }
            }
            int access = 0;
            switch (ctx->cause) {
            case 13: access = KERN_MAP_PERM_R; break;
            case 15: access = KERN_MAP_PERM_W; break;
            case 12: access = KERN_MAP_PERM_X; break;
            default: assert(0);
            }
            struct vm_aspace *as = thread_get_aspace(thread_current());
            if (as && vm_aspace_handle_page_fault(as, fault_addr, access))
                return;
        }
        show_crash(ctx);
        panic("stop.\n");
    }
}

static void idle_thread(void *ctx)
{
    void (*boot_handler)(void) = ctx;
    boot_handler();

    // This is bullshit of course.
    while (1)
        thread_reschedule();

    ints_enable();
    while (1)
        asm volatile("wfi");
}

void threads_init(void (*boot_handler)(void))
{
    // Set a dummy tp while we're switching to new thread. This gives the trap
    // handler a chance to catch kernel exceptions until a real thread pointer
    // is setup properly.
    struct thread dummy = {0};
    asm volatile("csrw sscratch, %[tp]\n"
                 "mv tp, %[tp]\n"
                 "csrw stvec, %[tr]\n"
        :
        : [tr] "r" (trap),
          [tp] "r" (&dummy)
        : "memory");

    struct thread *t = thread_create_kernel(idle_thread, boot_handler);
    if (!t)
        panic("Could not create idle thread.\n");
    thread_switch_to(t);
    panic("unreachable\n");
}
