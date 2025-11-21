/*
 * Fuzzer harness for DVCP
 * Copyright 2024 Google LLC
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Image structure from dvcp.c
struct Image {
    char header[4];
    int width;
    int height;
    char data[10];
};

// Declare the ProcessImage function (we'll link against dvcp.c or inline it)
// For fuzzing, we'll inline the vulnerable code directly

void stack_operation() {
    char buff[0x1000];
    (void)buff;
    // Don't actually recurse infinitely in fuzzer - just simulate
    // stack_operation();
}

int FuzzProcessImage(const uint8_t *data, size_t size) {
    // Need at least the size of Image struct
    if (size < sizeof(struct Image)) {
        return 0;
    }

    struct Image img;
    
    // Copy fuzzer input into Image structure
    memcpy(&img, data, sizeof(struct Image));

    // VULNERABILITY: Integer overflow
    int size1 = img.width + img.height;
    if (size1 <= 0) return 0;  // Prevent huge allocations
    if (size1 > 100000) return 0;  // Limit for fuzzing
    
    char* buff1 = (char*)malloc(size1);
    if (!buff1) return 0;

    // VULNERABILITY: Heap buffer overflow
    memcpy(buff1, img.data, sizeof(img.data));
    
    free(buff1);
    
    // VULNERABILITY: Double free
    if (size1 % 2 == 0) {
        free(buff1);
    } else {
        // VULNERABILITY: Use after free
        if (size1 % 3 == 0) {
            buff1[0] = 'a';
        }
    }

    // VULNERABILITY: Integer underflow
    int size2 = img.width - img.height + 100;
    if (size2 <= 0) return 0;
    if (size2 > 100000) return 0;
    
    char* buff2 = (char*)malloc(size2);
    if (!buff2) return 0;

    // VULNERABILITY: Heap buffer overflow
    memcpy(buff2, img.data, sizeof(img.data));

    // VULNERABILITY: Divide by zero
    if (img.height == 0) {
        free(buff2);
        return 0;  // Avoid divide by zero in fuzzer
    }
    int size3 = img.width / img.height;
    
    if (size3 < 0 || size3 > 10000) {
        free(buff2);
        return 0;
    }

    char buff3[10];
    char* buff4 = (char*)malloc(size3 > 0 ? size3 : 1);
    if (!buff4) {
        free(buff2);
        return 0;
    }
    
    memcpy(buff4, img.data, sizeof(img.data));

    // VULNERABILITY: Out-of-bounds read (OOBR) - stack
    if (size3 < 10) {
        char OOBR = buff3[size3];
        (void)OOBR;
    }
    
    // VULNERABILITY: Out-of-bounds read (OOBR) - heap
    if (size3 > 0) {  // Access one past the allocation
        volatile char OOBR_heap = buff4[size3];
        (void)OOBR_heap;
    }

    // VULNERABILITY: Out-of-bounds write (OOBW) - stack
    if (size3 < 10) {
        buff3[size3] = 'c';
    }
    
    // VULNERABILITY: Out-of-bounds write (OOBW) - heap
    buff4[size3] = 'c';

    if (size3 > 10) {
        // VULNERABILITY: Memory leak
        buff4 = 0;
    } else {
        free(buff4);
    }

    free(buff2);
    
    return 0;
}

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProcessImage(data, size);
}
