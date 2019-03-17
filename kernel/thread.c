#include "arch.h"
#include "handle.h"
#include "kernel.h"
#include "linked_list.h"
#include "mmu.h"
#include "page_alloc.h"
#include "page_internal.h"
#include "thread.h"
#include "thread_internal.h"
#include "time.h"
#include "virtual_memory.h"

// (overflows at sizes towards the end of the integer range)
#define PAGE_ALIGN_UP(x) (((x) + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1))

// Excluding unallocated guard pages (which need address space).
#define KERNEL_THREAD_SIZE PAGE_ALIGN_UP(PAGE_SIZE / 2 + sizeof(struct thread))
#define KERNEL_THREAD_PAGES (KERNEL_THREAD_SIZE / PAGE_SIZE)
#define THREAD_GUARD_PAGES 1
// Virtual address space usage per thread (including guard pages).
#define KERNEL_THREAD_VSIZE (KERNEL_THREAD_SIZE + THREAD_GUARD_PAGES * PAGE_SIZE)
#define KERNEL_THREAD_VPAGES (KERNEL_THREAD_VSIZE / PAGE_SIZE)

void trap(void);
void trap_return(void);
void thread_switch_asm(struct thread *t);
bool run_with_trap_asm(void *a, void *b);

static struct thread_list_head all_threads;
static struct thread_list_head waiting_threads;
static struct thread_list_head runnable_threads[THREAD_PRIORITY_NUM];

// Time at which the next scheduling decision should be made. Per CPU (?).
static uint64_t time_slice_end_time;

// (For simpler asm.)
static_assert(!(sizeof(struct asm_regs) & (STACK_ALIGNMENT - 1)), "");
static_assert(!(sizeof(struct thread) & (STACK_ALIGNMENT - 1)), "");

// Use a bitmap allocator with a static number of max. threads to manage the
// virtual address space for thread stacks. This is kind of dumb and inefficient,
// but due to the need for guard pages, they are the only kernel objects so far
// that need kernel virtual address space management. There's no other need for
// a static thread table, so replacing this with a more efficient and more
// flexible scheme should be easy, and is left to the non-existent reader.
#define MAX_THREADS (256 * 1024 * 1024 / KERNEL_THREAD_VSIZE)
static uint32_t thread_freemap[MAX_THREADS / 32];
static_assert(ARRAY_ELEMS(thread_freemap) * 32 == MAX_THREADS, "");
static uintptr_t thread_aspace_base;

struct thread *thread_create(void)
{
    struct mmu *kmmu = mmu_get_kernel();

    size_t index = MAX_THREADS;

    for (size_t n = 0; n < MAX_THREADS; n += 32) {
        uint32_t e = thread_freemap[n / 32];
        if (e) {
            for (size_t b = 0; b < 32; b++) {
                if (e & (1U << b)) {
                    index = n + b;
                    goto done;
                }
            }
        }
    }
    done:;

    if (index >= MAX_THREADS)
        return NULL;

    char *base = (void *)(thread_aspace_base + index * KERNEL_THREAD_VSIZE);

    uint64_t pages[KERNEL_THREAD_VPAGES];
    for (size_t n = 0; n < ARRAY_ELEMS(pages); n++)
        pages[n] = INVALID_PHY_ADDR;

    // Allocate memory for each page (except the guard page, which is simply
    // not touched, as all virt_alloc addresses should be initially unmapped).
    for (size_t n = THREAD_GUARD_PAGES; n < KERNEL_THREAD_VPAGES; n++) {
        int flags = MMU_FLAG_NEW | MMU_FLAG_RW;
        pages[n] = page_alloc_phy(1, PAGE_USAGE_THREAD);
        if (pages[n] == INVALID_PHY_ADDR)
            goto fail;
        if (!mmu_map(kmmu, base + n * PAGE_SIZE, pages[n], PAGE_SIZE, flags))
            goto fail;
    }

    struct thread *t = (void *)(base + KERNEL_THREAD_VSIZE - sizeof(*t));
    *t = (struct thread){
        .mmu = kmmu,
        .base = base,
        .user_context = ((struct asm_regs *)t) - 1,
        .state = THREAD_STATE_NO_CONTEXT,
        .priority = THREAD_PRIORITY_NORMAL,
    };

    LL_APPEND(&all_threads, t, all_threads);

    thread_freemap[index / 32]  &= ~(uint32_t)(1U << (index % 32));

    return t;

fail:
    for (size_t n = 0; n < KERNEL_THREAD_VPAGES; n++) {
        bool r = mmu_unmap(kmmu, base + n * PAGE_SIZE, PAGE_SIZE, 0);
        assert(r);
        page_free_phy(pages[n], 1);
    }
    return NULL;
}

void thread_free(struct thread *t)
{
    assert(t->refcount == 0); // handles still referencing it?
    assert(thread_current() != t);

    thread_set_aspace(t, NULL);
    thread_set_state(t, THREAD_STATE_DEAD);

    uintptr_t iaddr = (uintptr_t)t;
    assert(iaddr >= thread_aspace_base);
    size_t index = (iaddr - thread_aspace_base) / KERNEL_THREAD_VSIZE;
    assert(index < MAX_THREADS);

    char *base = (char *)(thread_aspace_base + index * KERNEL_THREAD_VSIZE);
    assert(base == t->base);

    LL_REMOVE(&all_threads, t, all_threads);

    // Unmap and free the pages; makes t pointer invalid.
    for (size_t n = 0; n < KERNEL_THREAD_VPAGES; n++) {
        void *addr = base + n * PAGE_SIZE;
        uint64_t phys;
        size_t page_size;
        int flags;
        if (!mmu_read_entry(t->mmu, addr, &phys, &page_size, &flags))
            panic("Internal error on freeing struct thread.\n");
        assert(page_size == PAGE_SIZE);
        page_free_phy(phys, 1);
        if (!mmu_unmap(t->mmu, addr, PAGE_SIZE, 0))
            panic("Internal error on freeing struct thread (2).\n");
    }

    thread_freemap[index / 32]  |= (1U << (index % 32));
}

void thread_set_kernel_context(struct thread *t, void (*fn)(void *ctx), void *ctx)
{
    assert(t->user_context && t->state == THREAD_STATE_NO_CONTEXT);
    struct asm_regs *regs = t->user_context;

    t->user_context = NULL;
    t->kernel_sp = regs;
    t->kernel_pc = trap_return;

    uintptr_t gp;
    asm("mv %0, gp" : "=r" (gp));
    regs->regs[2] = (uintptr_t)t;            // sp
    regs->regs[3] = gp;                      // gp
    regs->regs[4] = (uintptr_t)t;            // tp
    regs->regs[10] = (uintptr_t)ctx;         // a0

    regs->pc = (uintptr_t)fn;

    regs->status = (1 << 8);                 // set SPP (kernel mode)
    regs->status |= (2ULL << 32) | 0x80000;

    thread_set_state(t, THREAD_STATE_RUNNABLE);
}

bool thread_set_user_context(struct thread *t, struct asm_regs *user_regs)
{
    if (!t->user_context || t->state != THREAD_STATE_NO_CONTEXT)
        return false;

    t->kernel_sp = t->user_context;
    t->kernel_pc = trap_return;

    *t->user_context = *user_regs;
    t->user_context->status = (2ULL << 32) | 0x80000;

    thread_set_state(t, THREAD_STATE_RUNNABLE);

    return true;
}

void thread_set_aspace(struct thread *t, struct vm_aspace *aspace)
{
    if (t->aspace == aspace)
        return;

    if (t->aspace) {
        struct vm_aspace_owners *list = vm_aspace_get_owners(t->aspace);
        LL_REMOVE(list, t, aspace_siblings);
        if (!list->head) {
            // Before freeing the mmu struct, destroy the handle table, which
            // is a terrible mess.
            mmu_switch_to(t->mmu);
            handle_table_destroy(t->mmu);
            mmu_switch_to(thread_get_mmu(thread_current()));

            // Free aspace + mmu struct.
            vm_aspace_free(t->aspace);
        }
    }

    if (aspace) {
        struct vm_aspace_owners *list = vm_aspace_get_owners(aspace);
        LL_APPEND(list, t, aspace_siblings);
    }

    t->aspace = aspace;
    t->mmu = aspace ? vm_aspace_get_mmu(aspace) : mmu_get_kernel();
}

struct vm_aspace *thread_get_aspace(struct thread *t)
{
    return t->aspace;
}

struct mmu *thread_get_mmu(struct thread *t)
{
    return t->mmu;
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
    struct thread *next = NULL;

    // Assumes the thread is inserted into a "good" place in the runnable list
    // (such as at the end to give other threads a chance).
    if (cur->state == THREAD_STATE_FINE)
        thread_set_state(cur, THREAD_STATE_RUNNABLE);

    for (int n = THREAD_PRIORITY_NUM - 1; n >= 0; n--) {
        if (runnable_threads[n].head) {
            next = runnable_threads[n].head;
            break;
        }
    }

    // Normally, we have the idle thread for doing nothing. In particular, the
    // idle thread will enable IRQs in order not to freeze the shit, so it's
    // important to use it if nothing else is going on.
    if (!next)
        panic("No thread to schedule.\n");

    assert(next->state == THREAD_STATE_RUNNABLE);

    thread_set_state(next, THREAD_STATE_FINE);
    thread_switch_to(next);
}

static void thread_handle_timeout(struct thread *t)
{
    switch (t->state) {
    case THREAD_STATE_WAIT_FUTEX: {
        assert(t->futex);
        assert(t->futex->page->usage == PAGE_USAGE_USER);
        printf("futex timeout\n");
        // Remove from the singly-linked list.
        struct futex_waiter **p_head = &t->futex->page->u.user.futex_waiters;
        while (*p_head != t->futex)
            p_head = &(*p_head)->next;
        *p_head = t->futex->next;
        t->futex = NULL;
        thread_set_state(t, THREAD_STATE_RUNNABLE);
        break;
    }
    default:
        // (must have been in a state that waits)
        abort();
    }
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
    assert(t->state == THREAD_STATE_FINE);

    mmu_switch_to(t->mmu);

    thread_switch_asm(t);
}

static void update_timer(void)
{
    uint64_t next_time = time_slice_end_time;

    struct thread *t = waiting_threads.head;
    if (t && t->wait_timeout_time < next_time)
        next_time = t->wait_timeout_time;

    time_set_next_event(next_time);
}

enum thread_state thread_get_state(struct thread *t)
{
    return t->state;
}

void thread_set_state(struct thread *t, enum thread_state state)
{
    if (t->state == state)
        return;

    switch (t->state) {
    case THREAD_STATE_RUNNABLE:
        LL_REMOVE(&runnable_threads[t->priority], t, runnable);
        break;
    case THREAD_STATE_WAIT_FUTEX:
        LL_REMOVE(&waiting_threads, t, waiting);
        break;
    case THREAD_STATE_NO_CONTEXT:
    case THREAD_STATE_FINE:
        break;
    case THREAD_STATE_DEAD: // fallthrough; state can't be left
    default:
        abort();
    }

    t->state = state;

    switch (t->state) {
    case THREAD_STATE_RUNNABLE:
        LL_APPEND(&runnable_threads[t->priority], t, runnable);
        break;
    case THREAD_STATE_WAIT_FUTEX: {
        // Inserted in a sorted manner.
        struct thread *insert_before = NULL; // NULL => insert at end
        if (t->wait_timeout_time < UINT64_MAX) {
            // Look for the first entry that has a higher wakeup time. Naive; a
            // better implementation would probably use a heap or so.
            for (struct thread *cur = waiting_threads.head; cur;
                 cur = cur->waiting.next)
            {
                if (cur->wait_timeout_time > t->wait_timeout_time) {
                    insert_before = cur;
                    break;
                }
            }
        }
        LL_INSERT_BEFORE(&waiting_threads, insert_before, t, waiting);
        if (waiting_threads.head == t)
            update_timer();
        //printf("wait insert %p\n", t);
        break;
    }
    case THREAD_STATE_FINE:
    case THREAD_STATE_DEAD:
        break;
    case THREAD_STATE_NO_CONTEXT: // fallthrough: state can't be entered
    default:
        abort();
    }
}

void thread_set_priority(struct thread *t, enum thread_priority priority)
{
    if (t->priority == priority)
        return;

    // Temporarily switch to some other state to update the scheduler queues.
    enum thread_state tstate = t->state;
    if (tstate == THREAD_STATE_RUNNABLE)
        thread_set_state(t, THREAD_STATE_FINE);

    t->priority = priority;

    thread_set_state(t, tstate);
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

static bool handle_vm_pagefault(uintptr_t fault_addr, size_t cause_csr)
{
    if (fault_addr > MMU_ADDRESS_LOWER_MAX)
        return false;

    int access = 0;
    switch (cause_csr) {
    case 13: access = KERN_MAP_PERM_R; break;
    case 15: access = KERN_MAP_PERM_W; break;
    case 12: access = KERN_MAP_PERM_X; break;
    default: return false;
    }

    struct vm_aspace *as = thread_get_aspace(thread_current());
    return as && vm_aspace_handle_page_fault(as, (void *)fault_addr, access);
}

void c_trap(struct asm_regs *ctx)
{
    struct thread *t = thread_current();

    assert(!ints_disable());

    bool from_userspace = !(ctx->status & (1 << 8));

    if (from_userspace)
        t->user_context = ctx;

    if (ctx->cause == ((1ULL << 63) | 5)) {
        printf("timer IRQ\n");
        uint64_t now = time_get();
        // Currently fix timeslice at 1/4th seconds.
        time_slice_end_time = now + SECOND / 4;
        while (waiting_threads.head) {
            if (waiting_threads.head->wait_timeout_time > now)
                break;
            thread_handle_timeout(waiting_threads.head);
        }
        update_timer();
        thread_reschedule();
        /*static int cnt;
        if (cnt++ == 5)
            page_alloc_debug_dump();*/
    } else {
        // The RISC-V spec. doesn't define what most of the exception codes
        // actually mean (lol?). The intention is to catch all page faults that
        // are caused by missing mmu PTE flags.
        if (ctx->cause == 13 || ctx->cause == 15 || ctx->cause == 12) {
            uintptr_t fault_addr = ctx->tval;
            struct thread *t = thread_current();
            if (ctx->cause != 12 && t && t->trap_pc &&
                fault_addr >= t->trap_pagefault_lo &&
                fault_addr <= t->trap_pagefault_hi &&
                !t->trap_handler_running)
            {
                assert(!from_userspace);
                // The trap handler is normally used to safely access userspace.
                // In that case, the page fault could be resolved using the VM
                // system.
                t->trap_handler_running = true; // disallow recursive traps
                bool ok = handle_vm_pagefault(fault_addr, ctx->cause);
                t->trap_handler_running = false;
                if (ok)
                    goto done; // retry access
                // Otherwise invoke exception handler.
                ctx->regs[2] = t->trap_sp;
                ctx->pc = t->trap_pc;
                goto done;
            }
            if (from_userspace && handle_vm_pagefault(fault_addr, ctx->cause))
                goto done;
        }
        show_crash(ctx);
        panic("stop.\n");
    }

done:
    t->user_context = NULL;
}

bool run_trap_pagefaults(uintptr_t ok_lo, uintptr_t ok_hi, void (*fn)(void *),
                         void *fn_ctx)
{
    struct thread *t = thread_current();

    assert(!t->trap_pc); // attempting disallowed nested use?

    t->trap_pagefault_lo = ok_lo;
    t->trap_pagefault_hi = ok_hi;

    return run_with_trap_asm(fn, fn_ctx);
}

uint64_t futex_wake(struct phys_page *page, int offset, uint64_t max_wakeups)
{
    assert(page->usage == PAGE_USAGE_USER);
    struct futex_waiter **p_next = &page->u.user.futex_waiters;

    uint64_t woken = 0;

    while (max_wakeups) {
        struct futex_waiter *f = *p_next;
        if (!f)
            break;

        assert(f->page == page);
        assert(f->t->state == THREAD_STATE_WAIT_FUTEX);

        if (offset < 0 || f->offset == offset) {
            struct thread *t = f->t;
            //printf("futex waker %p\n", t);
            *p_next = f->next;
            f->result = 1;
            t->futex = NULL;
            thread_set_state(t, THREAD_STATE_RUNNABLE);
            max_wakeups--;
            woken++;
        } else {
            p_next = &f->next;
        }
    }

    if (woken)
        thread_reschedule();

    return woken;
}

int futex_wait(struct phys_page *page, int offset, uint64_t timeout_time)
{
    struct thread *t = thread_current();
    assert(page->usage == PAGE_USAGE_USER);

    struct futex_waiter f = {
        .t = t,
        .page = page,
        .offset = offset,
    };

    t->futex = &f;

    f.next = page->u.user.futex_waiters;
    page->u.user.futex_waiters = &f;

    t->wait_timeout_time = timeout_time;
    thread_set_state(t, THREAD_STATE_WAIT_FUTEX);
    thread_reschedule();

    assert(!t->futex); // proper wakeup unsets it

    return f.result;
}

static void idle_thread(void *ctx)
{
    void (*boot_handler)(void) = ctx;
    boot_handler();

    ints_enable();
    while (1)
        asm volatile("wfi");
}

void threads_init(void (*boot_handler)(void))
{
    size_t aspace_alloc = MAX_THREADS * KERNEL_THREAD_VSIZE;
    if ((char *)virt_alloc_end - (char *)virt_alloc_cur < aspace_alloc)
        panic("Not enough address space for thread table.\n");
    thread_aspace_base = (uintptr_t)virt_alloc_cur;
    virt_alloc_cur = (char *)virt_alloc_cur + aspace_alloc;

    for (size_t n = 0; n < ARRAY_ELEMS(thread_freemap); n++)
        thread_freemap[n] = ~(uint32_t)0;

    struct thread *t = thread_create();
    if (!t)
        panic("Could not create idle thread.\n");

    thread_set_kernel_context(t, idle_thread, boot_handler);
    thread_set_priority(t, THREAD_PRIORITY_IDLE);

    // (because we switch directly to the new thread)
    thread_set_state(t, THREAD_STATE_FINE);

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

    thread_switch_to(t);
    panic("unreachable\n");
}

// not great
void thread_fill_syscall_saved_regs(struct thread *t, struct asm_regs *regs)
{
    *regs = (struct asm_regs){
        .regs = {
            [1] = t->syscall_ra,
            [2] = t->syscall_sp,
            [3] = t->syscall_gp,
            [4] = t->syscall_tp,
            [8] = t->syscall_cs[0],
            [9] = t->syscall_cs[1],
        },
        .pc = t->syscall_pc,
    };
    for (size_t n = 2; n < 12; n++)
        regs->regs[n - 2 + 18] = t->syscall_cs[n];
}

static bool thread_handle_ref(struct handle *new, struct handle *old)
{
    assert(old->u.thread->refcount >= 0);
    *new = *old;
    new->u.thread->refcount += 1;
    return true;
}

static void thread_handle_unref(struct handle *h)
{
    assert(h->u.thread->refcount > 0);

    h->u.thread->refcount -= 1;
    if (h->u.thread->refcount == 0)
        thread_free(h->u.thread);
}

const struct handle_vtable handle_thread = {
    .name = "thread",
    .ref = thread_handle_ref,
    .unref = thread_handle_unref,
};
