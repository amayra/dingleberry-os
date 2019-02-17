include ../shared.mk

CFLAGS = $(COMMON_CFLAGS) -ffreestanding -mno-save-restore -mcmodel=medany -mexplicit-relocs -mno-relax

LDFLAGS = -T $(BUILD)/kernel.ld -melf64lriscv

OBJECTS = start.o boot.o libc_glue.o page_alloc.o slob.o mmu.o trap.o \
          syscalls.o thread.o \
          shared/libinsanity/printf.o \
          $(MUSL)/src/string/memcpy.o \
          $(MUSL)/src/string/memmove.o \
          $(MUSL)/src/string/memset.o \
          $(MUSL)/src/string/memcmp.o \
          $(MUSL)/src/string/strcmp.o \
          $(MUSL)/src/string/strlen.o \
          $(MUSL)/src/string/strncmp.o \

BUILD_TARGET = $(addprefix $(BUILD)/, $(TARGET))
BUILD_OBJECTS = $(addprefix $(BUILD)/, $(OBJECTS))
BUILD_DEPS = $(BUILD_OBJECTS:.o=.d) $(BUILD)/kernel.d

all: $(BUILD)/kernel.bin

clean:
	rm -rf $(BUILD)

$(BUILD)/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/kernel.ld: kernel.ld.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -E -P -g0 -DIN_LINKERSCRIPT -c -o $@ $<

$(BUILD)/kernel.elf: $(BUILD_OBJECTS) $(BUILD)/kernel.ld
	$(LD) $(LDFLAGS) -o $@ --start-group $(BUILD_OBJECTS) --end-group

$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
	# (Allocating the zeros will make sure BSS is cleared. Needs a little
	# less ASM. If anyone knows where Linux/RISC-V clears this when OpenSBI
	# is used, please call me.)
	$(OBJCOPY) -O binary --set-section-flags .bss=alloc,load,contents $< $@

-include $(BUILD_DEPS)
