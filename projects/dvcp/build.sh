#!/bin/bash -euxo pipefail
# $SRC=/src ; $OUT is where fuzz targets must be placed

cd "$SRC/dvcp"

# Build DVCP into $OUT (runner executes from /out)
$CC $CFLAGS -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    dvcp.c -o "$OUT/dvcp"

# Minimal harness (can switch to in-process later)
cat > dvcp_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f = fopen("input.bin", "wb");
  if (!f) return 0;
  fwrite(data, 1, size, f);
  fclose(f);
  (void)system("/out/dvcp input.bin");
  return 0;
}
EOF

$CC $CFLAGS -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    dvcp_fuzz.c -o "$OUT/dvcp_fuzz" $LIB_FUZZING_ENGINE

# Optional seed to kickstart coverage
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"
