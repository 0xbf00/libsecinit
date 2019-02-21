CC = clang

# CFLAGS were tweaked to resemble Apple's code as closely as possible.
CFLAGS = -fstack-protector \
		 -fno-unroll-loops \
		 -fno-inline-functions \
		 -O2 \
		 -dynamiclib -current_version 1.0.0 -compatibility_version 1.0.0
CFLAGS += -DTRACE
INSTALL_NAME = -install_name /usr/lib/system/libsystem_secinit.dylib
DEPS = libsecinit.c
TARGET = libsystem_secinit.dylib

mojave: CFLAGS += -DMAC_OS_MOJAVE
mojave: clean $(TARGET)
	@echo Built $(TARGET) for macOS Mojave.

$(TARGET): $(DEPS)
	$(CC) -o $(TARGET) $(DEPS) $(CFLAGS) $(INSTALL_NAME)

sierra: CFLAGS += -DMAC_OS_SIERRA
sierra: clean $(TARGET)
	@echo Built $(TARGET) for macOS Sierra.

high_sierra: CFLAGS += -DMAC_OS_HIGH_SIERRA
high_sierra: clean $(TARGET)
	@echo Built $(TARGET) for macOS High Sierra.

clean:
	@rm -f libsystem_secinit.dylib
	@rm -f *.o
