
#==============================================================================
# Makefile for RSA3072 / AES256CBC ARM Library Build
#
# Target: ARM Cortex-M3 static libraries (.lib)
# Toolchain: ARM Compiler 5 (armcc / armar)
#
# Usage:
#   make                - Build all libraries (rsa3072.lib + aes256cbc.lib)
#   make rsa3072        - Build rsa3072.lib only
#   make aes256cbc      - Build aes256cbc.lib only
#   make clean          - Remove all build artifacts
#==============================================================================

#------------------------------------------------------------------------------
# Include Options
#------------------------------------------------------------------------------

include BuildOption.mak

#------------------------------------------------------------------------------
# Source directories
#------------------------------------------------------------------------------

SRC_DIR = ..\..\Src
RSA3072_DIR = $(SRC_DIR)\rsa3072
AES256CBC_DIR = $(SRC_DIR)\aes256cbc

#------------------------------------------------------------------------------
# Output directories
#------------------------------------------------------------------------------

OUT_DIR          = _out
OBJ_DIR          = $(OUT_DIR)\obj
LIB_DIR          = $(OUT_DIR)\lib
INTERMEDIATE_DIR = $(OUT_DIR)\intermediate

#------------------------------------------------------------------------------
# Include paths
#------------------------------------------------------------------------------

C_INCLUDE   = -I$(RSA3072_DIR) -I$(AES256CBC_DIR)

#------------------------------------------------------------------------------
# Source files
#------------------------------------------------------------------------------

RSA3072_SRC = \
    $(RSA3072_DIR)\rsa3072.c \
    $(RSA3072_DIR)\bn384.c \
    $(RSA3072_DIR)\sha256.c

AES256CBC_SRC = \
    $(AES256CBC_DIR)\aes256cbc.c

RSA3072_OBJ = \
    $(OBJ_DIR)\rsa3072.o \
    $(OBJ_DIR)\bn384.o \
    $(OBJ_DIR)\sha256.o

AES256CBC_OBJ = \
    $(OBJ_DIR)\aes256cbc.o

#------------------------------------------------------------------------------
# Output files
#------------------------------------------------------------------------------

RSA3072_LIB = $(LIB_DIR)\rsa3072.lib
AES256CBC_LIB = $(LIB_DIR)\aes256cbc.lib

#------------------------------------------------------------------------------
# Build targets
#------------------------------------------------------------------------------

.PHONY: all rsa3072 aes256cbc clean

all: rsa3072 aes256cbc

rsa3072: $(RSA3072_LIB)
	$(info )
	$(info [DONE] $(RSA3072_LIB))

aes256cbc: $(AES256CBC_LIB)
	$(info )
	$(info [DONE] $(AES256CBC_LIB))

#------------------------------------------------------------------------------
# Archive: create static libraries
#------------------------------------------------------------------------------

$(RSA3072_LIB): $(RSA3072_OBJ) | $(LIB_DIR) $(INTERMEDIATE_DIR)
	$(info >> Archiving $(RSA3072_LIB))
	@$(ARCHIVE) --create $@ $^
	$(info >> Generating intermediate - rsa3072)
	@$(FROMELF) --text -s $@ > $(INTERMEDIATE_DIR)\rsa3072.txt
	@$(FROMELF) --text -z $@ > $(INTERMEDIATE_DIR)\rsa3072.lst

$(AES256CBC_LIB): $(AES256CBC_OBJ) | $(LIB_DIR) $(INTERMEDIATE_DIR)
	$(info >> Archiving $(AES256CBC_LIB))
	@$(ARCHIVE) --create $@ $^
	$(info >> Generating intermediate - aes256cbc)
	@$(FROMELF) --text -s $@ > $(INTERMEDIATE_DIR)\aes256cbc.txt
	@$(FROMELF) --text -z $@ > $(INTERMEDIATE_DIR)\aes256cbc.lst

#------------------------------------------------------------------------------
# Compile: RSA3072 sources
#------------------------------------------------------------------------------

$(OBJ_DIR)\rsa3072.o: $(RSA3072_DIR)\rsa3072.c | $(OBJ_DIR) $(INTERMEDIATE_DIR)
	$(info Compiling - $<)
	@$(COMPILE) $(C_FLAGS) $< -o $@

$(OBJ_DIR)\bn384.o: $(RSA3072_DIR)\bn384.c | $(OBJ_DIR) $(INTERMEDIATE_DIR)
	$(info Compiling - $<)
	@$(COMPILE) $(C_FLAGS) $< -o $@

$(OBJ_DIR)\sha256.o: $(RSA3072_DIR)\sha256.c | $(OBJ_DIR) $(INTERMEDIATE_DIR)
	$(info Compiling - $<)
	@$(COMPILE) $(C_FLAGS) $< -o $@

#------------------------------------------------------------------------------
# Compile: AES256CBC sources
#------------------------------------------------------------------------------

$(OBJ_DIR)\aes256cbc.o: $(AES256CBC_DIR)\aes256cbc.c | $(OBJ_DIR) $(INTERMEDIATE_DIR)
	$(info Compiling - $<)
	@$(COMPILE) $(C_FLAGS) $< -o $@

#------------------------------------------------------------------------------
# Create directories
#------------------------------------------------------------------------------

$(OBJ_DIR):
	@cmd /c if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)"

$(LIB_DIR):
	@cmd /c if not exist "$(LIB_DIR)" mkdir "$(LIB_DIR)"

$(INTERMEDIATE_DIR):
	@cmd /c if not exist "$(INTERMEDIATE_DIR)" mkdir "$(INTERMEDIATE_DIR)"

#------------------------------------------------------------------------------
# Clean
#------------------------------------------------------------------------------

clean:
	@cmd /c if exist "$(OUT_DIR)" rmdir /s /q "$(OUT_DIR)"
	$(info --- $(OUT_DIR) Clean Finished)

#------------------------------------------------------------------------------
# Dependency list
#------------------------------------------------------------------------------

-include ${RSA3072_OBJ:.o=.d}
-include ${AES256CBC_OBJ:.o=.d}
