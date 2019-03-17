#pragma once

#include <stdint.h>

struct kern_timespec;

// 1 second in kernel time units.
#define SECOND (1000ULL * 1000 * 1000)

void time_init(uint64_t timer_frequency);

// Return the current time in nanoseconds, using an unspecified base fixed at
// boot time, aka kernel time.
uint64_t time_get(void);

// Set next absolute kernel time at which an IRQ should happen.
void time_set_next_event(uint64_t time);

// Convert t to linear kernel time. Out of range clamped to [0, UINT64_MAX].
uint64_t time_from_timespec(struct kern_timespec *t);

// Convert linear kernel time to dst. Note that often, kernel time UINT64_MAX
// is used for "infinite", so this function sets *dst to the max. value as well.
void time_to_timespec(struct kern_timespec *dst, uint64_t src);
