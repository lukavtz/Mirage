/*
 * base64.c — Base64 decode utility
 *
 * Unified base64 decoding used by Chrome, Firefox, and other crypto modules.
 * Extracted from chrome_key.c mirage_base64_decode.
 */

#include "base64.h"
#include <string.h>

/* ── Base64 decode lookup table ───────────────────────────── */

static const int8_t BASE64_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x00-0x0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x10-0x1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 0x20-0x2F ('+'=62, '/'=63) */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,  /* 0x30-0x3F ('0'-'9'=52-61, '='=0) */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 0x40-0x4F ('A'-'O'=0-14) */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 0x50-0x5F ('P'-'Z'=15-25) */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 0x60-0x6F ('a'-'o'=26-40) */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 0x70-0x7F ('p'-'z'=41-51) */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int base64_decode(const char *input, size_t input_len,
                  unsigned char *out, size_t out_max) {
    if (input_len == 0 || input_len % 4 != 0) return -1;

    size_t max_out = (input_len / 4) * 3;
    if (out_max < max_out) return -1;

    size_t padding = 0;
    if (input_len >= 2 && input[input_len - 2] == '=') padding = 2;
    else if (input_len >= 1 && input[input_len - 1] == '=') padding = 1;

    size_t out_len = max_out - padding;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i += 4) {
        int8_t a = BASE64_DECODE[(unsigned char)input[i]];
        int8_t b = BASE64_DECODE[(unsigned char)input[i + 1]];
        int8_t c = BASE64_DECODE[(unsigned char)input[i + 2]];
        int8_t d = BASE64_DECODE[(unsigned char)input[i + 3]];

        if (a < 0 || b < 0) return -1;
        if (c < 0 && input[i + 2] != '=') return -1;
        if (d < 0 && input[i + 3] != '=') return -1;

        out[out_pos++] = (unsigned char)((a << 2) | (b >> 4));
        if (out_pos >= out_len) break;

        if (c >= 0) {
            out[out_pos++] = (unsigned char)(((b & 0xF) << 4) | (c >> 2));
            if (out_pos >= out_len) break;
        }
        if (d >= 0) {
            out[out_pos++] = (unsigned char)(((c & 0x3) << 6) | d);
            if (out_pos >= out_len) break;
        }
    }

    return (int)out_len;
}
