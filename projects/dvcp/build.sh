#!/bin/bash -euxo pipefail
# $SRC=/src ; $OUT is where fuzz targets must be placed

cd "$SRC/dvcp"

# Build DVCP into $OUT (runner executes from /out)
$CC $CFLAGS -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    dvcp.c -o "$OUT/dvcp"

# File-based harness that propagates child failures to the fuzzer process
cat > dvcp_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f = fopen("input.bin", "wb");
  if (!f) return 0;
  fwrite(data, 1, size, f);
  fclose(f);

  int status = system("/out/dvcp input.bin");

  // IMPORTANT: make the fuzzer crash when the child fails so libFuzzer saves a testcase
  if (status == -1) { __builtin_trap(); }
  if (WIFSIGNALED(status)) { __builtin_trap(); }
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) { __builtin_trap(); }

  return 0;
}
EOF

# Build the fuzzer -> /out
$CC $CFLAGS -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    dvcp_fuzz.c -o "$OUT/dvcp_fuzz" $LIB_FUZZING_ENGINE

# Optional seed to kickstart coverage
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"

# Ensure artifacts are saved where Buttercup/OSS-Fuzz look for them
cat > "$OUT/dvcp_fuzz.options" <<'OPTS'
[libfuzzer]
artifact_prefix=/out/
timeout=25
OPTS
