include ../shared.mk

BIN_CFLAGS = -Xlinker -zseparate-code -Xlinker -Ttext=0x200000 -Xlinker --build-id=none

MUSL_OBJECTS = crt.o crt_c.o musl_emu.o \
               $(MUSL)/src/string/memcpy.o \
               $(MUSL)/src/string/memmove.o \
               $(MUSL)/src/string/memset.o \
               $(MUSL)/src/string/memcmp.o \
               $(MUSL)/src/string/strcmp.o \
               $(MUSL)/src/string/strlen.o \
               $(MUSL)/src/string/strncmp.o \
               $(MUSL)/src/env/__libc_start_main.o \
               $(MUSL)/src/env/__environ.o \
               $(MUSL)/src/env/__init_tls.o \
               $(MUSL)/src/errno/__errno_location.o \
               $(MUSL)/src/process/fork.o \
               $(MUSL)/src/internal/libc.o \
               $(MUSL)/src/internal/syscall_ret.o \
               $(MUSL)/src/mman/mmap.o \
               $(MUSL)/src/mman/munmap.o \
               $(MUSL)/src/mman/mprotect.o \
               $(MUSL)/src/signal/block.o \
               $(MUSL)/src/stdio/ofl.o \
               $(MUSL)/src/thread/riscv64/__set_thread_area.o \
               $(MUSL)/src/thread/__lock.o \
               $(MUSL)/src/thread/__timedwait.o \
               $(MUSL)/src/thread/__wait.o \
               $(MUSL)/src/thread/default_attr.o \
               $(MUSL)/src/thread/pthread_create.o \
               $(MUSL)/src/thread/pthread_detach.o \
               $(MUSL)/src/thread/pthread_join.o \
               $(MUSL)/src/thread/pthread_mutex_lock.o \
               $(MUSL)/src/thread/pthread_mutex_timedlock.o \
               $(MUSL)/src/thread/pthread_mutex_trylock.o \
               $(MUSL)/src/thread/pthread_mutex_unlock.o \
               $(MUSL)/src/thread/pthread_self.o \
               $(MUSL)/src/thread/pthread_setcancelstate.o \
               $(MUSL)/src/thread/pthread_testcancel.o \
               $(MUSL)/src/thread/vmlock.o \
               $(MUSL)/src/time/clock_gettime.o \
               $(MUSL)/src/time/nanosleep.o \
               $(MUSL)/src/unistd/sleep.o \
               $(MUSL)/src/unistd/usleep.o \
               $(MUSL)/src/exit/exit.o \
               $(MUSL)/src/exit/_Exit.o \

# Musl's choice of warning flags. Respect them, so we don't get unwanted errors.
MUSL_WARN_CFLAGS = -Werror=implicit-function-declaration \
                   -Werror=implicit-int \
                   -Werror=pointer-sign \
                   -Werror=pointer-arith

MUSL_CFLAGS = $(CPU_CFLAGS) -std=c99 -nostdinc -ffreestanding $(MUSL_WARN_CFLAGS) \
              $(DEP_CFLAGS) -DCRT -D_XOPEN_SOURCE=700 $(OPT_CFLAGS) \
              -I$(MUSL)/arch/riscv64 -I$(MUSL)/arch/generic \
              -I$(MUSL)/src/include -I$(MUSL)/src/internal \
              -I$(MUSL)/obj/include -I$(MUSL)/include \
              -Iroot/include_general

USER_OBJECTS = main.o root/libinsanity/printf.o

USER_OBJECTS_CFLAGS = $(COMMON_CFLAGS)

TARGET = rootprocess

BUILD_MUSL_OBJECTS = $(addprefix $(BUILD)/, $(MUSL_OBJECTS))
$(BUILD_MUSL_OBJECTS): CFLAGS += $(MUSL_CFLAGS)

BUILD_USER_OBJECTS = $(addprefix $(BUILD)/, $(USER_OBJECTS))
$(BUILD_USER_OBJECTS): CFLAGS = $(USER_OBJECTS_CFLAGS)

BUILD_TARGET = $(addprefix $(BUILD)/, $(TARGET))
BUILD_OBJECTS = $(BUILD_MUSL_OBJECTS) $(BUILD_USER_OBJECTS)
BUILD_DEPS = $(BUILD_OBJECTS:.o=.d)

all: $(BUILD_TARGET)

clean:
	rm -rf $(BUILD)

$(BUILD)/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: %.s
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_TARGET): $(BUILD_OBJECTS)
	mkdir -p $(@D)
	$(CC) $(COMMON_CFLAGS) $(BIN_CFLAGS) -o $@ $(BUILD_OBJECTS)

-include $(BUILD_DEPS)
