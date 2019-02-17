include ../shared.mk

CFLAGS = $(COMMON_CFLAGS) -Xlinker -zseparate-code -Xlinker -Ttext=0x200000 -Xlinker --build-id=none

OBJECTS = crt.o main.o \
          shared/libinsanity/printf.o \
          $(MUSL)/src/string/memcpy.o \
          $(MUSL)/src/string/memmove.o \
          $(MUSL)/src/string/memset.o \
          $(MUSL)/src/string/memcmp.o \
          $(MUSL)/src/string/strcmp.o \
          $(MUSL)/src/string/strlen.o \
          $(MUSL)/src/string/strncmp.o \

TARGET = rootprocess

BUILD_TARGET = $(addprefix $(BUILD)/, $(TARGET))
BUILD_OBJECTS = $(addprefix $(BUILD)/, $(OBJECTS))
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

$(BUILD_TARGET): $(BUILD_OBJECTS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $(BUILD_OBJECTS)

-include $(BUILD_DEPS)
