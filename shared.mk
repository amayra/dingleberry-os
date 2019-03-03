# This is Debian's cross compiler.
CC = riscv64-linux-gnu-gcc-8
LD = riscv64-linux-gnu-ld
OBJCOPY = riscv64-linux-gnu-objcopy

BUILD = build

OPT_CFLAGS = -O1 -g -ggdb -static
WARN_CFLAGS = -Wall -Werror=format -Werror=implicit-function-declaration

# Get compiler freestanding include path. Pretty much for stdatomic.h.
# Without -nostdinc, the host include path (/usr/include) is added to the list
# of search paths, and we don't want that.
GCC_INCLUDE = $(shell $(CC) -print-file-name=include)

# One of the most important codegen options is -fno-PIE, which prevents gcc
# from generating idiotic GOT relocations instead of pure PC-relative addressing.
COMMON_CFLAGS = -MD -MP  $(WARN_CFLAGS) $(OPT_CFLAGS) -D_GNU_SOURCE \
                -mabi=lp64 -fno-PIE -march=rv64imafdc -mstrict-align \
                -fno-builtin-printf \
                -nostartfiles -nodefaultlibs -nostdlib -nostdinc \
                -isystem shared/include_sys/ \
                -isystem shared/musl/include/ \
                -isystem $(GCC_INCLUDE)

MUSL = shared/musl
