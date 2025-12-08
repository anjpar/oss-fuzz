#!/bin/bash -eu

cd $SRC/lwip/test/fuzz

# Build only the libraries, not the AFL fuzzers
CC=clang CFLAGS="$CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error" make clean
CC=clang CFLAGS="$CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error" make liblwipapps.a liblwipcommon.a

# Compile fuzz_common.o and stubs
$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c fuzz_common.c -o fuzz_common.o

$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c lwip_fuzzer_stubs.c -o lwip_fuzzer_stubs.o

# Compile each fuzzer to .o first
$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c fuzz_lwip_libfuzzer.c -o fuzz_lwip_libfuzzer.o

$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c fuzz_lwip_libfuzzer2.c -o fuzz_lwip_libfuzzer2.o

$CC $CFLAGS -O1 -fsanitize=fuzzer-no-link,address,undefined -Wno-error \
    -I../../src/include -I../../contrib/ports/unix/port/include -I. \
    -c fuzz_lwip_libfuzzer3.c -o fuzz_lwip_libfuzzer3.o

# Link fuzzer 1
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -fsanitize=address,undefined \
    fuzz_lwip_libfuzzer.o fuzz_common.o lwip_fuzzer_stubs.o \
    liblwipapps.a liblwipcommon.a -lm -o $OUT/fuzz_lwip_single

# Link fuzzer 2
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -fsanitize=address,undefined \
    fuzz_lwip_libfuzzer2.o fuzz_common.o lwip_fuzzer_stubs.o \
    liblwipapps.a liblwipcommon.a -lm -o $OUT/fuzz_lwip_multipacket

# Link fuzzer 3
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -fsanitize=address,undefined \
    fuzz_lwip_libfuzzer3.o fuzz_common.o lwip_fuzzer_stubs.o \
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
