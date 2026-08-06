/*
 * fuzz_json.c -- libFuzzer target for JSON extract
 * Build: clang -g -O1 -fsanitize=fuzzer,address -Iinclude -Isrc/parsers -std=c11 \
 *        -DTEST_JSON_EXTRACT_STANDALONE -o fuzz/fuzz_json fuzz/fuzz_json.c
 * Run:   fuzz/fuzz_json -max_len=4096
 */
#include <stdlib.h>
#include <string.h>

/* Forward declare json_extract_str if standalone */
#ifdef TEST_JSON_EXTRACT_STANDALONE
int json_extract_str(const char *json, const char *key, char *out, size_t out_size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) return 0;

    /* Null-terminate the input */
    char *json = (char *)malloc(size + 1);
    if (!json) return 0;
    memcpy(json, data, size);
    json[size] = '\0';

    char out[256];
    json_extract_str(json, "key", out, sizeof(out));
    json_extract_str(json, "name", out, sizeof(out));
    json_extract_str(json, "value", out, sizeof(out));

    free(json);
    return 0;
}
