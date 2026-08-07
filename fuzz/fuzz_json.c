/*
 * fuzz_json.c -- libFuzzer target for JSON extract
 * Build: clang -g -O1 -fsanitize=fuzzer,address -Iinclude -Isrc/parsers -std=c11 \
 *        -DTEST_JSON_EXTRACT_STANDALONE -o fuzz/fuzz_json fuzz/fuzz_json.c
 * Run:   fuzz/fuzz_json -max_len=4096
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* json_extract_str — embedded from cdp_grabber.c for fuzzing */
#ifdef TEST_JSON_EXTRACT_STANDALONE
#include <stdio.h>
static int json_extract_str(const char *json, const char *key,
                            char *out, size_t out_max) {
    char search[128];
    int slen = snprintf(search, sizeof(search), "\"%s\":\"", key);
    if (slen <= 0 || (size_t)slen >= sizeof(search)) return -1;
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += slen;
    size_t i = 0;
    while (p[i] && p[i] != '"' && i + 1 < out_max) {
        if (p[i] == '\\' && p[i + 1]) {
            if (p[i + 1] == '"') { out[i++] = '\\'; break; }
            switch (p[i + 1]) {
            case '\\': out[i++] = '\\'; break;
            case 'n':  out[i++] = '\n'; break;
            case 't':  out[i++] = '\t'; break;
            default:   out[i] = p[i + 1]; i++; break;
            }
            p += 2;
        } else {
            out[i] = p[i]; i++;
        }
    }
    out[i] = '\0';
    return (int)i;
}
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
