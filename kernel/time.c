#include "kernel.h"
#include "sbi.h"
#include "time.h"

#include <kernel/api.h>

static uint64_t timer_frequency;
static uint64_t base_ticks;

static uint64_t read_timer_ticks(void)
{
    uint64_t r;
    asm("rdtime %0" : "=r" (r));
    return r;
}

void time_init(uint64_t timer_frequency_)
{
    assert(!timer_frequency);
    timer_frequency = timer_frequency_;
    base_ticks = read_timer_ticks();
}

uint64_t time_get(void)
{
    uint64_t ticks = read_timer_ticks() - base_ticks;
    return ticks * SECOND / timer_frequency;
}

void time_set_next_event(uint64_t time)
{
    uint64_t ticks = time * timer_frequency / SECOND + base_ticks;
    sbi_set_timer(ticks);
}

uint64_t time_from_timespec(struct kern_timespec *t)
{
    if (t->sec < 0)
        return 0;
    if (t->sec > UINT64_MAX / SECOND)
        return UINT64_MAX;
    uint64_t res = t->sec * SECOND;
    if (UINT64_MAX - res < t->nsec)
        return UINT64_MAX;
    return res + t->nsec;
}

void time_to_timespec(struct kern_timespec *dst, uint64_t src)
{
    if (src == UINT64_MAX) {
        dst->sec = INT64_MAX;
        dst->nsec = SECOND - 1;
    } else {
        dst->sec = src / SECOND;
        dst->nsec = src % SECOND;
    }
}
