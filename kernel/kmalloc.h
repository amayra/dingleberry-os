#pragma once

#include <stddef.h>

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void *mallocz(size_t size);
void *reallocz(void *ptr, size_t size);
void free(void *ptr);
