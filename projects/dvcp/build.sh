#!/bin/bash -eu

cd "$SRC/dvcp"

# Build DVCP as a library (compile but don't link into executable)
$CC $CFLAGS -c dvcp.c -o dvcp.o

# Create fuzzer harness that calls ProcessImage directly
cat > dvcp_fuzz.cpp <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Declare the function from dvcp.c
extern "C" int ProcessImage(char* filename);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Write fuzz input to temp file
  char filename[] = "/tmp/fuzz_input_XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) return 0;
  
  write(fd, data, size);
  close(fd);
  
  // Call ProcessImage directly (no system() call)
  ProcessImage(filename);
  
  unlink(filename);
  return 0;
}
EOF

# Build the fuzzer by linking dvcp.o directly with the fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    dvcp_fuzz.cpp dvcp.o -o "$OUT/dvcp_fuzz"

# Seed corpus
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"
printf "TESTDATA" > "$OUT/dvcp_fuzz_seed_corpus/seed2"
printf "\x00\x01\x02\x03" > "$OUT/dvcp_fuzz_seed_corpus/seed3"
