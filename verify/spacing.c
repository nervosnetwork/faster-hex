#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
int main(void) {
    unsigned char *buffer = aligned_alloc(4096, 16384);
    if (!buffer) abort();
    memset(buffer, 0xaa, 16384);
    const size_t out[] = {0xe0, 0x10e0};
    const size_t in[] = {0x10e1, 0xd1};
    const size_t iterations = 300000;
    for (size_t j = 0; j < 8; ++j) {
        size_t k = (j % 4 == 1 || j % 4 == 2);
        uint64_t begin = now();
        for (size_t i = 0; i < iterations; ++i) {
            memcpy(buffer + out[k], buffer + in[k], 4096);
        }
        printf("spacing %+td, %.2f ns per 4096-byte libc copy\n",
               (ptrdiff_t)out[k] - (ptrdiff_t)in[k], (double)(now()-begin) / iterations);
    }
    free(buffer);
    return 0;
}
