/*
 * test_base64.c — unit tests for base64_decode (RFC 4648 vectors)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* base64.h is in src/utils/, not reachable via TEST_CFLAGS — forward-declare */
int base64_decode(const char *input, size_t input_len,
                  unsigned char *out, size_t out_max);

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  PASS: %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name) do { tests_run++; printf("  FAIL: %s\n", name); } while(0)

/* ── local encoder for roundtrip tests ─────────────────────── */
static const char B64_TBL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode_local(const unsigned char *in, size_t in_len,
                               char *out, size_t out_max) {
    size_t needed = ((in_len + 2) / 3) * 4;
    if (out_max < needed + 1) return -1;
    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        unsigned int n = (unsigned int)in[i] << 16;
        if (i + 1 < in_len) n |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < in_len) n |= (unsigned int)in[i + 2];
        out[j++] = B64_TBL[(n >> 18) & 0x3F];
        out[j++] = B64_TBL[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < in_len) ? B64_TBL[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < in_len) ? B64_TBL[n & 0x3F] : '=';
    }
    out[j] = '\0';
    return (int)j;
}

/* ── helper: decode and compare ────────────────────────────── */
static int expect_decode(const char *b64, const char *expected, size_t exp_len) {
    unsigned char buf[256];
    int got = base64_decode(b64, strlen(b64), buf, sizeof(buf));
    if (got < 0) return -1;
    if ((size_t)got != exp_len) return -2;
    if (memcmp(buf, expected, exp_len) != 0) return -3;
    return 0;
}

/* ── RFC 4648 §10 test vectors ─────────────────────────────── */

static void test_decode_empty(void) {
    /* "" → input_len==0 should return -1 (no 4-char group) */
    unsigned char buf[8];
    int got = base64_decode("", 0, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_empty"); return; }
    TEST("test_decode_empty");
}

static void test_decode_f(void) {
    if (expect_decode("Zg==", "f", 1) != 0) { TEST_FAIL("test_decode_f"); return; }
    TEST("test_decode_f");
}

static void test_decode_fo(void) {
    if (expect_decode("Zm8=", "fo", 2) != 0) { TEST_FAIL("test_decode_fo"); return; }
    TEST("test_decode_fo");
}

static void test_decode_foo(void) {
    if (expect_decode("Zm9v", "foo", 3) != 0) { TEST_FAIL("test_decode_foo"); return; }
    TEST("test_decode_foo");
}

static void test_decode_foob(void) {
    if (expect_decode("Zm9vYg==", "foob", 4) != 0) { TEST_FAIL("test_decode_foob"); return; }
    TEST("test_decode_foob");
}

static void test_decode_fooba(void) {
    if (expect_decode("Zm9vYmE=", "fooba", 5) != 0) { TEST_FAIL("test_decode_fooba"); return; }
    TEST("test_decode_fooba");
}

static void test_decode_foobar(void) {
    if (expect_decode("Zm9vYmFy", "foobar", 6) != 0) { TEST_FAIL("test_decode_foobar"); return; }
    TEST("test_decode_foobar");
}

/* ── error paths ───────────────────────────────────────────── */

static void test_decode_invalid_char(void) {
    unsigned char buf[32];
    /* input not multiple of 4 → rejected before char validation */
    int got = base64_decode("Zm9v!", 5, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_invalid_char"); return; }
    TEST("test_decode_invalid_char");
}

static void test_decode_invalid_char_aligned(void) {
    unsigned char buf[32];
    /* 4-char group with invalid char '!' at position 2 */
    int got = base64_decode("Zm!v", 4, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_invalid_char_aligned"); return; }
    TEST("test_decode_invalid_char_aligned");
}

static void test_decode_bad_padding_pos0(void) {
    unsigned char buf[32];
    /* '=' at position 0 — should be rejected */
    int got = base64_decode("=m9v", 4, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_bad_padding_pos0"); return; }
    TEST("test_decode_bad_padding_pos0");
}

static void test_decode_bad_padding_pos1(void) {
    unsigned char buf[32];
    /* '=' at position 1 — should be rejected */
    int got = base64_decode("Z=9v", 4, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_bad_padding_pos1"); return; }
    TEST("test_decode_bad_padding_pos1");
}

static void test_decode_not_multiple_of_4(void) {
    unsigned char buf[32];
    int got = base64_decode("Zg", 2, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_not_multiple_of_4"); return; }
    TEST("test_decode_not_multiple_of_4");
}

/* ── buffer too small ──────────────────────────────────────── */

static void test_decode_buf_too_small(void) {
    unsigned char buf[1]; /* need 3 bytes for "Zm9v" → "foo" */
    int got = base64_decode("Zm9v", 4, buf, sizeof(buf));
    if (got != -1) { TEST_FAIL("test_decode_buf_too_small"); return; }
    TEST("test_decode_buf_too_small");
}

/* ── roundtrip: encode then decode ─────────────────────────── */

static void test_roundtrip(void) {
    const char *inputs[] = {
        "f", "fo", "foo", "foob", "fooba", "foobar",
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
    };
    for (int i = 0; i < (int)(sizeof(inputs) / sizeof(inputs[0])); i++) {
        const char *src = inputs[i];
        size_t src_len = strlen(src);
        char encoded[256];
        unsigned char decoded[256];

        int enc_len = base64_encode_local((const unsigned char *)src, src_len,
                                          encoded, sizeof(encoded));
        if (enc_len < 0) { TEST_FAIL("test_roundtrip (encode)"); return; }

        int dec_len = base64_decode(encoded, (size_t)enc_len, decoded, sizeof(decoded));
        if (dec_len < 0) { TEST_FAIL("test_roundtrip (decode)"); return; }
        if ((size_t)dec_len != src_len || memcmp(decoded, src, src_len) != 0) {
            TEST_FAIL("test_roundtrip (mismatch)");
            return;
        }
    }
    TEST("test_roundtrip");
}

static void test_roundtrip_binary(void) {
    unsigned char bin[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xFF, 0xFE};
    char encoded[64];
    unsigned char decoded[64];
    size_t bin_len = sizeof(bin);

    int enc_len = base64_encode_local(bin, bin_len, encoded, sizeof(encoded));
    if (enc_len < 0) { TEST_FAIL("test_roundtrip_binary (encode)"); return; }

    int dec_len = base64_decode(encoded, (size_t)enc_len, decoded, sizeof(decoded));
    if (dec_len < 0) { TEST_FAIL("test_roundtrip_binary (decode)"); return; }
    if ((size_t)dec_len != bin_len || memcmp(decoded, bin, bin_len) != 0) {
        TEST_FAIL("test_roundtrip_binary (mismatch)");
        return;
    }
    TEST("test_roundtrip_binary");
}

/* ── main ──────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_base64 ===\n");

    test_decode_empty();
    test_decode_f();
    test_decode_fo();
    test_decode_foo();
    test_decode_foob();
    test_decode_fooba();
    test_decode_foobar();

    test_decode_invalid_char();
    test_decode_invalid_char_aligned();
    test_decode_bad_padding_pos0();
    test_decode_bad_padding_pos1();
    test_decode_not_multiple_of_4();

    test_decode_buf_too_small();

    test_roundtrip();
    test_roundtrip_binary();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
