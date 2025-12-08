#!/bin/bash -eu

cd $SRC/lwip/test/fuzz

# Build lwIP libraries with fuzzing instrumentation (but skip AFL fuzzers)
CC=clang CFLAGS="$CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error" make clean
CC=clang CFLAGS="$CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error" make liblwipapps.a liblwipcommon.a

# Compile fuzz_common.o separately with correct flags
$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c fuzz_common.c -o fuzz_common.o

# Build fuzzer 1: SINGLE mode
$CXX $CXXFLAGS -O1 $LIB_FUZZING_ENGINE \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    fuzz_lwip_libfuzzer.c fuzz_common.o lwip_fuzzer_stubs.c \
    liblwipapps.a liblwipcommon.a -lm -o $OUT/fuzz_lwip_single

# Build fuzzer 2: MULTIPACKET mode
$CXX $CXXFLAGS -O1 $LIB_FUZZING_ENGINE \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    fuzz_lwip_libfuzzer2.c fuzz_common.o lwip_fuzzer_stubs.c \
    liblwipapps.a liblwipcommon.a -lm -o $OUT/fuzz_lwip_multipacket

# Build fuzzer 3: MULTIPACKET_TIME with all apps
$CXX $CXXFLAGS -O1 $LIB_FUZZING_ENGINE \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    fuzz_lwip_libfuzzer3.c fuzz_common.o lwip_fuzzer_stubs.c \
    liblwipapps.a liblwipcommon.a -lm -o $OUT/fuzz_lwip_full

# Copy seed corpus
mkdir -p $OUT/fuzz_lwip_single_seed_corpus
mkdir -p $OUT/fuzz_lwip_multipacket_seed_corpus
mkdir -p $OUT/fuzz_lwip_full_seed_corpus

cp inputs/tcp/* $OUT/fuzz_lwip_single_seed_corpus/ 2>/dev/null || true
cp inputs/udp/* $OUT/fuzz_lwip_single_seed_corpus/ 2>/dev/null || true
cp inputs/icmp/* $OUT/fuzz_lwip_single_seed_corpus/ 2>/dev/null || true

cp inputs/tcp/* $OUT/fuzz_lwip_multipacket_seed_corpus/ 2>/dev/null || true
cp inputs/udp/* $OUT/fuzz_lwip_multipacket_seed_corpus/ 2>/dev/null || true

cp inputs/*/* $OUT/fuzz_lwip_full_seed_corpus/ 2>/dev/null || true
