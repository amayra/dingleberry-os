include ../shared.mk

CFLAGS = $(COMMON_CFLAGS) -ffreestanding -mno-save-restore -mcmodel=medany -mexplicit-relocs -mno-relax

LDFLAGS = -T $(BUILD)/kernel.ld -melf64lriscv

OBJECTS = start.o boot.o libc_glue.o page_alloc.o slob.o mmu.o trap.o kmalloc.o \
          syscalls.o thread.o virtual_memory.o handle.o time.o ipc.o \
          root/libinsanity/printf.o \
          $(MUSL)/src/string/memcpy.o \
          $(MUSL)/src/string/memmove.o \
          $(MUSL)/src/string/memset.o \
          $(MUSL)/src/string/memcmp.o \
          $(MUSL)/src/string/strcmp.o \
          $(MUSL)/src/string/strlen.o \
          $(MUSL)/src/string/strncmp.o \

BUILD_TARGET = $(addprefix $(BUILD)/, $(TARGET))
BUILD_OBJECTS = $(addprefix $(BUILD)/, $(OBJECTS))
BUILD_DEPS = $(BUILD_OBJECTS:.o=.d) $(BUILD)/kernel.d $(BUILD)/asm_offsets.d

# Make all sources dependent on generated headers. This is needed so when
# building the first target that contains the generated header does not fail
# (as neither the dependency nor the generated header exist at that time).
# To prevent that _everything_ is rebuilt when anything the generated header
# depends on changes, order-only dependencies ("|") are used. This means
# building any targets with that dependency will make sure the pre-generated
# header is _created_ (even if it's outdated!), so the normal auto-generated
# dependencies are used instead. Quite hacky, but somehow works out.
# Also, making this an intermediate target instead of a variable breaks it.
# Is there a better way?
PRE = $(BUILD)/asm_offsets.h

all: $(BUILD)/kernel.bin

clean:
	rm -rf $(BUILD)

$(BUILD)/%.o: %.c | $(PRE)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.o: %.S | $(PRE)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/kernel.ld: kernel.ld.S | $(PRE)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -E -P -g0 -DIN_LINKERSCRIPT -c -o $@ $<

$(BUILD)/asm_offsets.s: asm_offsets.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -S -o $@ $<

$(BUILD)/asm_offsets.h: $(BUILD)/asm_offsets.s
	gawk -F '|' '{if($$1 ~ /[ \t]+O></){ sub(/struct /, "", $$2); gsub(/\./, "_", $$2); $$2 = toupper($$2) ; print "#define "$$2" "$$3}}' < $< > $@

$(BUILD)/kernel.elf: $(BUILD_OBJECTS) $(BUILD)/kernel.ld
	$(LD) $(LDFLAGS) -o $@ --start-group $(BUILD_OBJECTS) --end-group

$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
# (Allocating the zeros will make sure BSS is cleared. Could also clear it with
# ASM. Or a better boot loader. Never hope that the memory starts out with 0.)
	$(OBJCOPY) -O binary --set-section-flags .bss=alloc,load,contents $< $@

.PHONY: all clean

-include $(BUILD_DEPS)
