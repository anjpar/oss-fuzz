#!/bin/bash -eu

# Instead of compiling dvcp.c, just compile ProcessImage as a separate unit
# Extract just the ProcessImage function
$CC $CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -c -x c - -o $SRC/dvcp_funcs.o << 'DVCP_CODE'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// Copy just the Image struct and helper functions from dvcp.c
// Exclude the main() function
// Include the actual dvcp.c content here without main()
DVCP_CODE

# Build the fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE \
    $SRC/dvcp_fuzz_linked.c \
    $SRC/dvcp_funcs.o \
    -o $OUT/dvcp_fuzz

mkdir -p $OUT/dvcp_fuzz_seed_corpus  
echo -ne "IMG\x00\x01\x00\x00\x00\x01\x00\x00\x00AAAAAAAAAA" > $OUT/dvcp_fuzz_seed_corpus/seed1
