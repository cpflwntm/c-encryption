
#------------------------------------------------------------------------------
# Toolchain
#------------------------------------------------------------------------------

TOOLCHAIN_DIR = C:\Keil\ARM\ARMCC\bin

COMPILE = $(TOOLCHAIN_DIR)\armcc
ARCHIVE = $(TOOLCHAIN_DIR)\armar
FROMELF = $(TOOLCHAIN_DIR)\fromelf

#------------------------------------------------------------------------------
# C Compiler option flags
#------------------------------------------------------------------------------

C_CORE      = --cpu Cortex-M3

C_OPTIMIZE  = -O3 --apcs=interwork --split_sections \
              --interleave --enum_is_int --C99

C_DEBUG     = -g

C_WARNING   = --diag_suppress 1,61,66,494,550

C_ASM       = --asm --asm_dir $(INTERMEDIATE_DIR)

C_DEP       = --no_depend_system_headers --depend=${OBJ_DIR}\${notdir ${@:.o=.d}}

C_FLAGS     = -c $(C_CORE) $(C_OPTIMIZE) $(C_DEBUG) $(C_WARNING) $(C_DEP) \
              $(C_INCLUDE) $(C_ASM)
