#!/bin/bash -eu

cd "$SRC/dvcp"

# Extract just the ProcessImage function into a separate file
cat > dvcp_lib.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ProcessImage(char* filename) {
    FILE *fp;
    char header[4];
    int width, height;
    
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        return 1;
    }
    
    // Read header
    if (fread(header, 1, 3, fp) != 3) {
        fclose(fp);
        return 1;
    }
    header[3] = '\0';
    
    if (strcmp(header, "IMG") != 0) {
        fclose(fp);
        return 1;
    }
    
    // Read dimensions
    if (fread(&width, sizeof(int), 1, fp) != 1 ||
        fread(&height, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return 1;
    }
    
    // Buffer overflow vulnerability!
    char buffer[100];
    int data_size = width * height;
    
    if (fread(buffer, 1, data_size, fp) != data_size) {
        fclose(fp);
        return 1;
    }
    
    fclose(fp);
    return 0;
}
EOF

# Build the library (no main function conflict)
$CC $CFLAGS -c dvcp_lib.c -o dvcp.o

# Create fuzzer harness
cat > dvcp_fuzz.cpp <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" int ProcessImage(char* filename);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[] = "/tmp/fuzz_input_XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) return 0;
  
  write(fd, data, size);
  close(fd);
  
  ProcessImage(filename);
  
  unlink(filename);
  return 0;
}
EOF

# Build fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    dvcp_fuzz.cpp dvcp.o -o "$OUT/dvcp_fuzz"

# Seed corpus
mkdir -p "$OUT/dvcp_fuzz_seed_corpus"
printf "IMG" > "$OUT/dvcp_fuzz_seed_corpus/seed1"
printf "TESTDATA" > "$OUT/dvcp_fuzz_seed_corpus/seed2"
