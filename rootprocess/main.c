#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <kernel/api.h>
#include <kernel/ipc_stubs.h>
#include <kernel/stubs.h>

int foo[4097];
int foo2[4097]={1};
const int foo3[4097]={2};
const int foo4[4097]={3};

static void other_thread(int num)
{
    printf("other thread\n");
    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread%d)\n", num);
    }
}

void thread_cr(int num)
{
    size_t stack_size = 4096 * 4;
    void *stack = kern_mmap(KERN_HANDLE_INVALID, (void *)-1, stack_size,
                    KERN_MAP_FORK_COPY | KERN_MAP_PERM_W | KERN_MAP_PERM_R,
                    -1, 0);
    assert(!KERN_MMAP_FAILED(stack));

    struct kern_thread_regs regs = {0};
    regs.regs[2] = (uintptr_t)stack + stack_size;
    regs.regs[10] = num;
    regs.pc = (uintptr_t)other_thread;

    printf("stack: %p-%p\n", stack, (void *)regs.regs[2]);

    int64_t h = kern_thread_create(KERN_HANDLE_INVALID, false);
    assert(KERN_IS_HANDLE_VALID(h));

    int r = kern_thread_set_context(h, &regs);
    assert(r >= 0);
}


int dataseg = 123;

pthread_mutex_t testmutex = PTHREAD_MUTEX_INITIALIZER;
int crown_jewels;

static void *musl_thread(void *a)
{
    printf("hello from a musl thread\n");
    for (int n = 0; n < 3; n++) {
        printf("lock... from %s (%d)\n", __PRETTY_FUNCTION__, n);
        pthread_mutex_lock(&testmutex);
        printf("locked! from %s\n", __PRETTY_FUNCTION__);
        assert(!crown_jewels);
        crown_jewels = 1;
        struct timespec ts = {.tv_sec = 1};
        nanosleep(&ts, &ts);
        printf("unlock from %s\n", __PRETTY_FUNCTION__);
        assert(crown_jewels);
        crown_jewels = 0;
        pthread_mutex_unlock(&testmutex);
        //kern_yield();
    }
    return (void *)45678;
}

static void *detached_thread(void *a)
{
    printf("detaching and exiting\n");
    pthread_detach(pthread_self());
    return NULL;
}

static void *cont_thread(void *a)
{
    struct timespec ts = {.tv_sec = 1};
    nanosleep(&ts, &ts);
    printf("hello from %s\n", __PRETTY_FUNCTION__);
    int rf = fork();
    assert(rf >= 0);
    if (rf > 0) {
        printf("hello from a forked process, exiting immediately.\n");
        pthread_exit(NULL);
    }
    printf("meh.\n");
    while(1);
    return NULL;
}

static void *ipc_thread(void *parg)
{
    kern_handle port = *(kern_handle *)parg;
    void *rep_ud;
    kern_handle rep_port;
    size_t msg[KERN_IPC_REG_ARGS + 2] = {3,4,5,6,7,8,9,10, 0xaabb, 0xccdd};
    size_t rmsg[KERN_IPC_REG_ARGS + 10] = {0};
    int r = kern_ipc_call(port, msg, sizeof(msg), rmsg, sizeof(rmsg));
    printf("r=%d\n", r);
    assert(r >= 0);
    printf("reply:\n");
    for (int n = 0; n < r / sizeof(size_t); n++)
        printf("   a%d = %08zx\n", n, rmsg[n]);
    return NULL;
}


int main(void)
{
    // And this is why we did all this crap.
    printf("Hello world! (From userspace.)\n");

    struct kern_timespec ts;
    int r = kern_get_time(&ts);
    assert(r >= 0);
    printf("it is now: %ld %ld\n", (long)ts.sec, (long)ts.nsec);

    pthread_t res;

    kern_handle li = kern_ipc_listener_create();
    printf("listener: %ld\n", li);

    kern_handle ta = kern_ipc_target_create(li, 0xA123456E);
    printf("target: %ld\n", ta);

    r = pthread_create(&res, NULL, ipc_thread, &ta);

    //sleep(1);
    printf("start wait ipc\n");
    void *req_ud;
    kern_handle req_port;
    size_t msg[KERN_IPC_REG_ARGS];
    size_t mem_recv_buf[123];
    struct kern_ipc_args args = {
        .recv_size_max = sizeof(mem_recv_buf),
        .recv = mem_recv_buf,
    };
    r = kern_ipc_full(0, li, &args, &req_ud, &req_port, msg);
    printf("ipc wait listen r=%d\n", r);
    assert(r > 0);
    printf("port: %ld ud: %p memsz=%zd\n", req_port, req_ud, args.recv_size);
    for (int n = 0; n < KERN_IPC_REG_ARGS; n++)
        printf("   a%d = %08zx\n", n, msg[n]);
    for (int n = 0; n < args.recv_size / sizeof(size_t); n++)
        printf("   m%d = %08zx\n", n, mem_recv_buf[n]);
    size_t reply[KERN_IPC_REG_ARGS] = {0xDEAD, 0xBEEF, 0xBEEE, 0xF00D, 0x123, 0x456, 6, 7};
    size_t mem_send_buf[2] = {0xeeff, 0xffdd};
    struct kern_ipc_args rargs = {
        .send_size = sizeof(mem_send_buf),
        .send = mem_send_buf,
    };
    r = kern_ipc_full(req_port, 0, &rargs, &req_ud, &req_port, reply);
    printf("ipc send reply r=%d\n", r);
    while(1);

#if 0
    // Dummy futex call to wait a while
    uint32_t dummy = 123;
    ts.sec += 2;
    printf("wait for 2 seconds\n");
    kern_call4(KERN_FN_FUTEX, KERN_FUTEX_WAIT, (uintptr_t)&ts, (uintptr_t)&dummy, 123);
    printf("done\n");
#endif

    r = pthread_create(&res, NULL, musl_thread, (void *)1234);
    printf("res: %d\n", r);
    assert(r == 0);

    for (int n = 0; n < 10; n++) {
        printf("lock... from %s (%d)\n", __PRETTY_FUNCTION__, n);
        pthread_mutex_lock(&testmutex);
        printf("locked! from %s\n", __PRETTY_FUNCTION__);
        assert(!crown_jewels);
        crown_jewels = 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 333 * 1000 * 1000};
        nanosleep(&ts, &ts);
        printf("unlock from %s\n", __PRETTY_FUNCTION__);
        assert(crown_jewels);
        crown_jewels = 0;
        pthread_mutex_unlock(&testmutex);
        //kern_yield();
    }

    void *ret = NULL;
    r = pthread_join(res, &ret);

    printf("pthread_join => %d %p\n", r, ret);

    r = pthread_create(&res, NULL, detached_thread, NULL);
    assert(r == 0);

    printf("waiting for detached thread...\n");
    struct timespec pts = {.tv_sec = 1};
    nanosleep(&pts, &pts);
    printf("thread should have gone away.\n");

    r = pthread_create(&res, NULL, cont_thread, NULL);
    assert(r == 0);

    // The main thread is slightly special. Also, this doesn't free the
    // stack... because it's impossible on Linux.
    pthread_exit(NULL);

    while(1);

    thread_cr(2);
    thread_cr(3);

    printf("before: %d\n", dataseg);

    int64_t hfork = kern_thread_create(KERN_HANDLE_INVALID, true);
    assert(KERN_IS_HANDLE_VALID(hfork));
    int t = kern_copy_aspace(KERN_HANDLE_INVALID, hfork, true);
    printf("----- fork: %d, %ld\n", t, (long)hfork);
    assert(t >= 0);

    volatile int counter = !t * 40 + 10; // force on stack

    printf("after: %d\n", dataseg);
    if (!t)
        dataseg = counter;
    asm volatile("");
    printf("after overwrite: %d\n", dataseg);

    while (1) {
        asm volatile("wfi");
        printf("wfi wakeup (thread1) fork=%s cnt=%d\n", t?"child":"parent", counter++);
        if (counter == 53 && !t) {
            printf("close forked thread: %d\n", kern_close(hfork));
        }
    }
    return 0;
}

