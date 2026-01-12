# Makefile for Henix NPU × llama2.c integration

# Compiler and flags
CC = gcc
CFLAGS = -O3 -fopenmp
LDFLAGS = -lm

# ARM64 cross-compiler (optional)
ARM_CC = aarch64-linux-gnu-gcc
ARM_CFLAGS = -O3 -march=armv8-a -static
ARM_LDFLAGS = -lm

# Targets
TARGET = llama2_henix
ARM_TARGET = llama2_henix_aarch64

# Source files (exclude run.c which is for reference)
SRC = llama2.c henix_runtime.c

# Build rules
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

arm64: $(ARM_TARGET)

$(ARM_TARGET): $(SRC)
	$(ARM_CC) $(ARM_CFLAGS) $^ -o $@ $(ARM_LDFLAGS)

clean:
	rm -f $(TARGET) $(ARM_TARGET)

.PHONY: all arm64 clean