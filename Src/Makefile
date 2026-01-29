#
# Makefile for RSA 3072 Signature Verification and AES-256-CBC Decryption Test
#
# Requirements:
#   - OpenSSL (headers and libraries)
#
# For F/W porting: Only the rsa3072/ and aes256cbc/ folders are needed (no OpenSSL dependency)
#

# Compiler settings
CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS =

# OS detection for clean commands
ifeq ($(OS),Windows_NT)
    RM = cmd /c del /f /q
    RM_SUBDIR = cmd /c del /f /q
    PATHSEP = \\
else
    RM = rm -f
    RM_SUBDIR = rm -f
    PATHSEP = /
endif

# Minimal RSA3072 library paths
RSA3072_DIR     = rsa3072

# Minimal AES256CBC library paths
AES256CBC_DIR   = aes256cbc

# OpenSSL paths (adjust for your installation)
OPENSSL_DIR = C:/Program Files (x86)/OpenSSL-Win32
OPENSSL_INCLUDES = -I. -I$(RSA3072_DIR) -I$(AES256CBC_DIR) -I"$(OPENSSL_DIR)/include"
OPENSSL_LDFLAGS = -L. -L"$(OPENSSL_DIR)/lib" -lssl -lcrypto

# Output
TARGET = openssl_test

# Minimal RSA3072 source files
RSA3072_SRC = \
    $(RSA3072_DIR)/rsa3072.c \
    $(RSA3072_DIR)/bn384.c \
    $(RSA3072_DIR)/sha256.c

RSA3072_OBJ = $(RSA3072_SRC:.c=.o)
RSA3072_TARGET = rsa3072_test

# Minimal AES256CBC source files
AES256CBC_SRC = \
    $(AES256CBC_DIR)/aes256cbc.c

AES256CBC_OBJ = $(AES256CBC_SRC:.c=.o)
AES256CBC_TARGET = aes256cbc_test

# Phony targets
.PHONY: all clean test help rsa3072 rsa3072-test rsa3072-size rsa3072-clean aes256cbc aes256cbc-size aes256cbc-clean

#============================================================================
# Default Target: OpenSSL Test (Static + Loop Test)
#============================================================================

all: $(TARGET)

# Build test program
$(TARGET): main.o $(RSA3072_OBJ) $(AES256CBC_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(OPENSSL_LDFLAGS)
	@echo ""
	@echo "Build complete: $(TARGET)"
	@echo "Run './$(TARGET)' to test"

# Compile main.c
main.o: main.c
	$(CC) $(CFLAGS) $(OPENSSL_INCLUDES) -c -o $@ $<

# Run test
test: $(TARGET)
	./$(TARGET)

#============================================================================
# Minimal RSA3072 Library (for F/W porting, ~3.4KB)
#============================================================================

# Build RSA3072 library objects
rsa3072: $(RSA3072_OBJ)
	@echo ""
	@echo "RSA3072 library built: $(RSA3072_OBJ)"

# Compile RSA3072 sources (with size optimization)
$(RSA3072_DIR)/%.o: $(RSA3072_DIR)/%.c
	$(CC) -Wall -Wextra -Os -ffunction-sections -fdata-sections -I$(RSA3072_DIR) -c -o $@ $<

# Build and run RSA3072 standalone test
$(RSA3072_TARGET): $(RSA3072_OBJ) $(RSA3072_DIR)/test_rsa3072.o
	$(CC) -Wl,--gc-sections -o $@ $^
	@echo ""
	@echo "Build complete: $(RSA3072_TARGET)"

$(RSA3072_DIR)/test_rsa3072.o: $(RSA3072_DIR)/test_rsa3072.c
	$(CC) -Wall -Wextra -Os -I$(RSA3072_DIR) -c -o $@ $<

rsa3072-test: $(RSA3072_TARGET)
	./$(RSA3072_TARGET)

# Show RSA3072 code size
rsa3072-size: $(RSA3072_OBJ)
	@echo ""
	@echo "=== RSA3072 Library Size ==="
	size $(RSA3072_OBJ)
	@echo ""

# Clean RSA3072 objects
rsa3072-clean:
ifeq ($(OS),Windows_NT)
	-$(RM) $(RSA3072_TARGET) $(RSA3072_TARGET).exe 2>NUL
	-$(RM) $(RSA3072_DIR)$(PATHSEP)*.o 2>NUL
else
	-$(RM) $(RSA3072_TARGET) $(RSA3072_OBJ) $(RSA3072_DIR)/test_rsa3072.o
endif

#============================================================================
# Minimal AES256CBC Library (for F/W porting, ~2KB)
#============================================================================

# Build AES256CBC library objects
aes256cbc: $(AES256CBC_OBJ)
	@echo ""
	@echo "AES256CBC library built: $(AES256CBC_OBJ)"

# Compile AES256CBC sources (with size optimization)
$(AES256CBC_DIR)/%.o: $(AES256CBC_DIR)/%.c
	$(CC) -Wall -Wextra -Os -ffunction-sections -fdata-sections -I$(AES256CBC_DIR) -c -o $@ $<

# Show AES256CBC code size
aes256cbc-size: $(AES256CBC_OBJ)
	@echo ""
	@echo "=== AES256CBC Library Size ==="
	size $(AES256CBC_OBJ)
	@echo ""

# Clean AES256CBC objects
aes256cbc-clean:
ifeq ($(OS),Windows_NT)
	-$(RM) $(AES256CBC_TARGET) $(AES256CBC_TARGET).exe 2>NUL
	-$(RM) $(AES256CBC_DIR)$(PATHSEP)*.o 2>NUL
else
	-$(RM) $(AES256CBC_TARGET) $(AES256CBC_OBJ)
endif

#============================================================================
# Clean
#============================================================================

clean: rsa3072-clean aes256cbc-clean
ifeq ($(OS),Windows_NT)
	-$(RM) $(TARGET) $(TARGET).exe 2>NUL
	-$(RM) main.o *.o nul NUL 2>NUL
else
	-$(RM) $(TARGET) $(TARGET).exe
	-$(RM) main.o *.o nul
endif

#============================================================================
# Help
#============================================================================

help:
	@echo "RSA 3072 Signature Verification and AES-256-CBC Decryption Test"
	@echo ""
	@echo "Default target (requires OpenSSL):"
	@echo "  all          - Build test program (default)"
	@echo "  test         - Build and run test"
	@echo ""
	@echo "Minimal RSA3072 library (for F/W porting, ~3.4KB):"
	@echo "  rsa3072      - Build minimal RSA3072 library objects"
	@echo "  rsa3072-test - Build and run RSA3072 standalone test"
	@echo "  rsa3072-size - Show RSA3072 code size"
	@echo "  rsa3072-clean- Clean RSA3072 objects"
	@echo ""
	@echo "Minimal AES256CBC library (for F/W porting, ~2KB):"
	@echo "  aes256cbc      - Build minimal AES256CBC library objects"
	@echo "  aes256cbc-size - Show AES256CBC code size"
	@echo "  aes256cbc-clean- Clean AES256CBC objects"
	@echo ""
	@echo "Common:"
	@echo "  clean        - Remove all build artifacts"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Quick start:"
	@echo "  make         - Build test program"
	@echo "  make test    - Build and run"
	@echo ""
	@echo "F/W porting:"
	@echo "  Copy rsa3072/ and/or aes256cbc/ folder to your project"
	@echo "  make rsa3072-size    - Check RSA3072 code size"
	@echo "  make aes256cbc-size  - Check AES256CBC code size"

#
# For F/W porting:
#
# 1. Replace CC with your cross-compiler (e.g., arm-none-eabi-gcc)
# 2. Add appropriate CFLAGS for your target (-mcpu=cortex-m3, etc.)
# 3. Remove or adapt LDFLAGS
# 4. Integrate into your build system (CMake, Keil, IAR, etc.)
#
# Example for Cortex-M3:
#   CC = arm-none-eabi-gcc
#   CFLAGS = -mcpu=cortex-m3 -mthumb -Os -ffunction-sections -fdata-sections
#   LDFLAGS = -Wl,--gc-sections -specs=nosys.specs
#
# Library sizes (ARM Thumb-2, -Os):
#   - rsa3072/   : ~3.4 KB (RSA-3072 signature verification + SHA-256)
#   - aes256cbc/ : ~2 KB (AES-256-CBC decryption only)
#
