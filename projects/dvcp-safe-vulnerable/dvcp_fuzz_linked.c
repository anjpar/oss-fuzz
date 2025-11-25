/*
 * Fuzzer harness that links against actual dvcp.c
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>     // For write, close, unlink
#include <fcntl.h>      // For mkstemp

// Declare the function from dvcp.c
int ProcessImage(char* filename);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 18) {
        return 0;
    }

    // Write fuzzer input to a temporary file
    char tmpfile[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd == -1) return 0;
    
    write(fd, data, size);
    close(fd);
    
    // Call the actual ProcessImage function from dvcp.c
    ProcessImage(tmpfile);
    
    // Clean up
    unlink(tmpfile);
    
    return 0;
}
