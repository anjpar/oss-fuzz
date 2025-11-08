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

# =========================
# Post-build export to $OUT
# =========================
# Buttercup/OSS-Fuzz expect fuzz targets in $OUT (/out in the build container).
# This block collects artifacts from the local build and exports them.

set -e

# 1) Resolve OUT (set by OSS-Fuzz runner; default to /out for safety)
: "${OUT:=/out}"
echo "[dvcp/build.sh] Exporting fuzz artifacts to \$OUT = ${OUT}"

# 2) Known local output dir observed during your run:
#    .../oss-fuzz/build/out/dvcp/{dvcp_fuzz,dvcp,llvm-symbolizer}
LOCAL_OUT="$(pwd)/build/out/dvcp"

# 3) If that directory exists, copy everything (preserve perms; include dotfiles)
if [ -d "$LOCAL_OUT" ]; then
  mkdir -p "$OUT"
  cp -a "$LOCAL_OUT"/. "$OUT"/ || true
  echo "[dvcp/build.sh] Copied artifacts from $LOCAL_OUT -> $OUT"
else
  echo "[dvcp/build.sh] NOTE: Local output dir not found: $LOCAL_OUT"
fi

# 4) Fallback: copy likely fuzz targets discovered anywhere under project
FOUND_ANY=0
while IFS= read -r -d '' BIN; do
  mkdir -p "$OUT"
  cp -a "$BIN" "$OUT"/ || true
  echo "[dvcp/build.sh] Copied fuzz binary: $BIN -> $OUT/"
  FOUND_ANY=1
done < <(find . -type f \( -name 'dvcp_fuzz' -o -name '*fuzz*' -o -name 'dvcp' \) -perm -111 -size +8k -print0 2>/dev/null || true)

# 5) Optional: copy seeds/dictionaries/options if present
for sub in seeds corpus; do
  if [ -d "$sub" ]; then
    mkdir -p "$OUT/$sub"
    cp -a "$sub"/. "$OUT/$sub"/ || true
    echo "[dvcp/build.sh] Copied $sub -> $OUT/$sub/"
  fi
done

for f in *.dict *.options; do
  if [ -f "$f" ]; then
    mkdir -p "$OUT"
    cp -a "$f" "$OUT"/ || true
    echo "[dvcp/build.sh] Copied config: $f -> $OUT/"
  fi
done

if [ "$FOUND_ANY" -eq 0 ] && [ ! -d "$LOCAL_OUT" ]; then
  echo "[dvcp/build.sh] WARNING: No fuzz artifacts were found to export to \$OUT" >&2
fi
# =========================
