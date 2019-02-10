include ../shared.mk

ROOT=..

CFLAGS = $(COMMON_CFLAGS) -nostartfiles -nodefaultlibs -nostdlib -nostdinc -ffreestanding -mno-save-restore -mcmodel=medany -mexplicit-relocs -mno-relax -MD -MP -O0 -g  -ggdb

LDFLAGS = -T kernel.ld -melf64lriscv

OBJECTS = start.o boot.o libc_glue.o page_alloc.o slob.o \
          $(ROOT)/libc/libinsanity/printf.o \
          $(MUSL)/src/string/memcpy.o \
          $(MUSL)/src/string/memmove.o \
          $(MUSL)/src/string/memset.o \
          $(MUSL)/src/string/memcmp.o \
          $(MUSL)/src/string/strcmp.o \
          $(MUSL)/src/string/strlen.o \
          $(MUSL)/src/string/strncmp.o \

DEP_FILES = $(OBJECTS:.o=.d) kernel.d

all: kernel.bin

clean:
	rm -f kernel.elf kernel.bin kernel.ld $(OBJECTS) $(DEP_FILES)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

kernel.ld: kernel.ld.S
	$(CC) $(CFLAGS) -E -P -g0 -DIN_LINKERSCRIPT -c -o $@ $<

kernel.elf: $(OBJECTS) kernel.ld
	$(LD) $(LDFLAGS) -o $@ --start-group $(OBJECTS) --end-group

kernel.bin: kernel.elf
	# (Allocating the zeros will make sure BSS is cleared. Needs a little
	# less ASM. If anyone knows where Linux/RISC-V clears this, please call
	# me.)
	$(OBJCOPY) -O binary --set-section-flags .bss=alloc,load,contents $< $@

-include $(DEP_FILES)
