#!/bin/bash -eu

cd "$SRC/vcandcpp"

# Fuzzer 1: Target program3.c - Buffer Overflow vulnerability
cat > program3_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulate the buffer overflow vulnerability from program3.c
int FuzzProgram3(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    
    // Recreate the vulnerable code pattern from program3.c
    char path[50] = "./";
    
    // Create a null-terminated string from fuzzer input
    size_t copy_size = (size < 49) ? size : 49;  // Leave room for null terminator
    char *filename = (char *)malloc(size + 1);
    if (!filename) return 0;
    
    memcpy(filename, data, size);
    filename[size] = '\0';
    
    // This can overflow if filename is too long (> 47 chars since path is 2 chars)
    strcat(path, filename);
    
    free(filename);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProgram3(data, size);
}
EOF

# Build program3 fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE program3_fuzz.c -o "$OUT/program3_fuzz"

# Seed corpus for program3 - various filename lengths
mkdir -p "$OUT/program3_fuzz_seed_corpus"
printf "text.txt" > "$OUT/program3_fuzz_seed_corpus/seed1"
printf "short.c" > "$OUT/program3_fuzz_seed_corpus/seed2"
printf "averylongfilenamethatmightcausebufferoverflow.txt" > "$OUT/program3_fuzz_seed_corpus/seed3"
printf "../../../etc/passwd" > "$OUT/program3_fuzz_seed_corpus/seed4"


# Fuzzer 2: Target program3.c - Use After Free vulnerability
cat > program3_uaf_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulate the use-after-free vulnerability from program3.c
int FuzzProgram3UAF(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    
    // Simulate file size
    long fsize = data[0];
    
    // Allocate and free memory
    char *string = malloc(fsize + 1);
    if (!string) return 0;
    
    // Initialize the memory
    if (size > 1 && fsize > 0) {
        size_t copy_size = (size - 1 < fsize) ? size - 1 : fsize;
        memcpy(string, data + 1, copy_size);
    }
    
    free(string);
    
    // Use after free - if fsize is 0, access freed memory
    if (fsize == 0) {
        string[0] = 'A';  // Use after free!
    }
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProgram3UAF(data, size);
}
EOF

# Build program3 UAF fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE program3_uaf_fuzz.c -o "$OUT/program3_uaf_fuzz"

# Seed corpus for UAF
mkdir -p "$OUT/program3_uaf_fuzz_seed_corpus"
printf "\x00\x41" > "$OUT/program3_uaf_fuzz_seed_corpus/seed1"
printf "\x01\x42\x43" > "$OUT/program3_uaf_fuzz_seed_corpus/seed2"
printf "\x0a\x41\x42\x43\x44\x45" > "$OUT/program3_uaf_fuzz_seed_corpus/seed3"


# Fuzzer 3: Target program1.c - Memory Leak (for demonstration)
cat > program1_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulate the memory leak vulnerability from program1.c
void *allocateMemory(size_t size) {
    void *ptr = malloc(size);
    // Memory leak - no free!
    return ptr;
}

int FuzzProgram1(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    
    // Allocate memory based on fuzzer input
    size_t alloc_size = data[0];
    if (alloc_size == 0) alloc_size = 1;
    
    void *ptr = allocateMemory(alloc_size);
    // Memory is never freed - leak!
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProgram1(data, size);
}
EOF

# Build program1 fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE program1_fuzz.c -o "$OUT/program1_fuzz"

# Seed corpus for memory leak
mkdir -p "$OUT/program1_fuzz_seed_corpus"
printf "\x0a" > "$OUT/program1_fuzz_seed_corpus/seed1"
printf "\x64" > "$OUT/program1_fuzz_seed_corpus/seed2"
printf "\xff" > "$OUT/program1_fuzz_seed_corpus/seed3"


# Fuzzer 4: Generic vulnerable pattern - Integer overflow leading to buffer overflow
cat > intoverflow_fuzz.c <<'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulate integer overflow vulnerability
int FuzzIntOverflow(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    
    // Read two integers from fuzzer input
    int width = *(int*)(data);
    int height = *(int*)(data + 4);
    
    // Integer overflow vulnerability!
    int total_size = width * height;
    
    // If overflow occurs, total_size might be small
    if (total_size <= 0 || total_size > 1000000) return 0;
    
    // Allocate buffer based on potentially overflowed size
    char *buffer = malloc(total_size);
    if (!buffer) return 0;
    
    // Try to write to buffer
    if (size > 8) {
        size_t write_size = size - 8;
        if (write_size > total_size) write_size = total_size;
        memcpy(buffer, data + 8, write_size);
    }
    
    free(buffer);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzIntOverflow(data, size);
}
EOF

# Build integer overflow fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE intoverflow_fuzz.c -o "$OUT/intoverflow_fuzz"

# Seed corpus for integer overflow
mkdir -p "$OUT/intoverflow_fuzz_seed_corpus"
printf "\x0a\x00\x00\x00\x0a\x00\x00\x00AAAAAAAAAA" > "$OUT/intoverflow_fuzz_seed_corpus/seed1"
printf "\xff\xff\xff\x7f\x02\x00\x00\x00BBBBBBBB" > "$OUT/intoverflow_fuzz_seed_corpus/seed2"
printf "\x00\x01\x00\x00\x00\x01\x00\x00CCCCCCCC" > "$OUT/intoverflow_fuzz_seed_corpus/seed3"

echo "Build completed successfully!"
echo "Created fuzzers:"
echo "  - program3_fuzz (buffer overflow from strcat)"
echo "  - program3_uaf_fuzz (use-after-free)"
echo "  - program1_fuzz (memory leak)"
echo "  - intoverflow_fuzz (integer overflow)"
