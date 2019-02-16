#pragma once

#include "kernel.h"

struct aspace {
    bool is_kernel;
    uint64_t root_pt;

    struct {
        struct thread *head, *tail;
    } owners;

    struct {
        struct aspace *prev, *next;
    } all_aspaces;
};
