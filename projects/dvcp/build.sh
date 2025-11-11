#!/bin/bash -eu

# Build DVCP target
cd "$SRC/dvcp"

# Build the vulnerable program using provided flags
$CC $CFLAGS -c dvcp.c -o dvcp.o
$CC $CFLAGS dvcp.o -o "$OUT/dvcp"

# Create the fuzzer harness
cat > dvcp_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Write fuzz input to temp file
  FILE *f = fopen("/tmp/dvcp_input.bin", "wb");
  if (!f) return 0;
  fwrite(data, 1, size, f);
  fclose(f);
  
  // Execute the target with the input
  int status = system("/out/dvcp /tmp/dvcp_input.bin");
  
  // Propagate crashes to the fuzzer
  if (status == -1) { __builtin_trap(); }
  if (WIFSIGNALED(status)) { __builtin_trap(); }
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) { __builtin_trap(); }
  
  unlink("/tmp/dvcp_input.bin");
  return 0;
}
EOF

# Build the fuzzer using CXX (CRITICAL for Buttercup)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    dvcp_fuzz.c -o "$OUT/dvcp_fuzz"

# Create seed corpus
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"

# Add more diverse seeds
printf "TESTDATA" > "$OUT/dvcp_fuzz_seed_corpus/seed2"
printf "\x00\x01\x02\x03" > "$OUT/dvcp_fuzz_seed_corpus/seed3"
