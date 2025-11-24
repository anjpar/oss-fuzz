#!/bin/bash -eu

# Build dvcp.c as an object file
$CC $CFLAGS -c $SRC/dvcp/dvcp.c -o $SRC/dvcp.o

# Build the fuzzer and link with dvcp.o
$CC $CFLAGS $LIB_FUZZING_ENGINE \
    -I$SRC/dvcp \
    $SRC/dvcp_fuzz_linked.c \
    $SRC/dvcp.o \
    -o $OUT/dvcp_fuzz

# Create seed corpus
mkdir -p $OUT/dvcp_fuzz_seed_corpus
echo -ne "IMG\x00\x01\x00\x00\x00\x01\x00\x00\x00AAAAAAAAAA" > $OUT/dvcp_fuzz_seed_corpus/seed1
