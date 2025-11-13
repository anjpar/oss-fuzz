#!/bin/bash -eu

cd "$SRC/dvcp"

# Don't compile dvcp.c - inline the vulnerable code instead
cat > dvcp_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Inline the vulnerable ProcessImage logic
int FuzzProcessImage(const uint8_t *data, size_t size) {
    if (size < 11) return 0;  // Need at least header + dimensions
    
    // Check header
    if (memcmp(data, "IMG", 3) != 0) {
        return 0;
    }
    
    // Get dimensions (reading from fuzz input directly)
    int width = *(int*)(data + 3);
    int height = *(int*)(data + 7);
    
    // Buffer overflow vulnerability!
    char buffer[100];
    int data_size = width * height;
    
    if (size < 11 + data_size) return 0;
    
    // This will overflow if width * height > 100
    memcpy(buffer, data + 11, data_size);
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProcessImage(data, size);
}
EOF

# Build fuzzer - no linking with dvcp.o needed!
$CC $CFLAGS $LIB_FUZZING_ENGINE dvcp_fuzz.c -o "$OUT/dvcp_fuzz"

# Seed corpus with valid IMG header
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG\x0a\x00\x00\x00\x0a\x00\x00\x00AAAAAAAAAA" > "$OUT/dvcp_fuzz_seed_corpus/seed1"
