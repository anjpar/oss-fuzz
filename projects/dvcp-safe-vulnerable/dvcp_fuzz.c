/*
 * Fuzzer harness for DVCP - Version 2 (More Reproducible)
 * Copyright 2024 Google LLC
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct Image {
    char header[4];
    int width;
    int height;
    char data[10];
};

int FuzzProcessImage(const uint8_t *data, size_t size) {
    if (size < sizeof(struct Image)) {
        return 0;
    }

    struct Image img;
    memcpy(&img, data, sizeof(struct Image));

    // VULNERABILITY: Integer overflow
    // Relaxed bounds checking - allow more values through
    int size1 = img.width + img.height;
    if (size1 <= 0 || size1 > 50000) return 0;  // Increased from 100000
    
    char* buff1 = (char*)malloc(size1);
    if (!buff1) return 0;

    // VULNERABILITY: Heap buffer overflow
    // This is the main bug - always copy 10 bytes regardless of allocation size
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
    // More permissive bounds
    if (size2 <= 0 || size2 > 50000) return 0;
    
    char* buff2 = (char*)malloc(size2);
    if (!buff2) return 0;

    // VULNERABILITY: Heap buffer overflow
    memcpy(buff2, img.data, sizeof(img.data));

    // VULNERABILITY: Divide by zero - still skip for stability
    if (img.height == 0) {
        free(buff2);
        return 0;
    }
    int size3 = img.width / img.height;
    
    // More permissive bounds
    if (size3 < 0 || size3 > 5000) {
        free(buff2);
        return 0;
    }

    char buff3[10] = {0};
    char* buff4 = (char*)malloc(size3 > 0 ? size3 : 1);
    if (!buff4) {
        free(buff2);
        return 0;
    }
    
    // VULNERABILITY: Heap buffer overflow
    memcpy(buff4, img.data, sizeof(img.data));

    // VULNERABILITY: Out-of-bounds read - stack
    // More likely to trigger
    if (size3 >= 0 && size3 < 20) {
        volatile char OOBR = buff3[size3];
        (void)OOBR;
    }
    
    // VULNERABILITY: Out-of-bounds read - heap
    // Fixed the tautological comparison
    if (size3 > 0) {
        volatile char OOBR_heap = buff4[size3];
        (void)OOBR_heap;
    }

    // VULNERABILITY: Out-of-bounds write - stack
    if (size3 >= 0 && size3 < 20) {
        buff3[size3] = 'c';
    }
    
    // VULNERABILITY: Out-of-bounds write - heap
    // Always trigger if size3 is valid
    if (size3 > 0 && size3 < 5000) {
        buff4[size3] = 'c';
    }

    // VULNERABILITY: Memory leak
    if (size3 > 10) {
        buff4 = 0;
    } else {
        free(buff4);
    }

    free(buff2);
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return FuzzProcessImage(data, size);
}
