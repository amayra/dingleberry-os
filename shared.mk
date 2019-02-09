# This is Debian's cross compiler.
CC = riscv64-linux-gnu-gcc-8
LD = riscv64-linux-gnu-ld
OBJCOPY = riscv64-linux-gnu-objcopy

WARN_CFLAGS = -Wall -Werror=format -Werror=implicit-function-declaration

# One of the most important codegen options is -fno-PIE, which prevents gcc
# from generating idiotic GOT relocations instead of pure PC-relative addressing.
COMMON_CFLAGS = $(WARN_CFLAGS) -D_GNU_SOURCE \
                -mabi=lp64 -fno-PIE -march=rv64imafd -mstrict-align \
                -isystem $(ROOT)/libc/include/ \
                -isystem $(ROOT)/libc/musl/include/

MUSL = $(ROOT)/libc/musl