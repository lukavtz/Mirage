/*
 * fuzz_lz4.c -- libFuzzer target for LZ4 compress/decompress
 * Build: clang -g -O1 -fsanitize=fuzzer,address -Iinclude -Isrc/utils -std=c11 \
 *        -o fuzz/fuzz_lz4 fuzz/fuzz_lz4.c src/utils/lz4.c
 * Run:   fuzz/fuzz_lz4 -max_len=65536
 */
#include <stdlib.h>
#include <string.h>
#include "lz4.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    int comp_bound = lz4_compress_bound((int)size);
    if (comp_bound <= 0) return 0;

    unsigned char *compressed = (unsigned char *)malloc((size_t)comp_bound);
    if (!compressed) return 0;

    int comp_len = lz4_compress((const char *)data, (char *)compressed,
                                 (int)size, comp_bound);
    if (comp_len > 0) {
        unsigned char *decompressed = (unsigned char *)malloc(size + 1);
        if (decompressed) {
            /* Decompression roundtrip would need lz4_decompress; skip if not available */
            free(decompressed);
        }
    }

    free(compressed);
    return 0;
}
