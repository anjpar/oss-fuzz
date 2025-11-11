#!/bin/bash -eu

cd "$SRC/dvcp"

# Build the vulnerable program
$CC $CFLAGS -c dvcp.c -o dvcp.o
$CC $CFLAGS dvcp.o -o "$OUT/dvcp"

# Create fuzzer harness with proper C++ linkage
cat > dvcp_fuzz.cpp <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f = fopen("/tmp/dvcp_input.bin", "wb");
  if (!f) return 0;
  fwrite(data, 1, size, f);
  fclose(f);
  
  int status = system("/out/dvcp /tmp/dvcp_input.bin");
  
  if (status == -1) { __builtin_trap(); }
  if (WIFSIGNALED(status)) { __builtin_trap(); }
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) { __builtin_trap(); }
  
  unlink("/tmp/dvcp_input.bin");
  return 0;
}
EOF

# Build as C++ file (note: .cpp extension)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    dvcp_fuzz.cpp -o "$OUT/dvcp_fuzz"

# Seed corpus
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"
