/*
 * test_crypto.c — ChaCha20-Poly1305 AEAD roundtrip tests
 *
 * Tests chacha_poly_encrypt / chacha_poly_decrypt for:
 *   - Basic roundtrip (encrypt then decrypt recovers plaintext)
 *   - Empty plaintext
 *   - Associated data integrity
 *   - Tag tamper detection
 *   - Wrong key rejection
 *   - Wrong nonce rejection
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "chacha_poly.h"

static void test_roundtrip_basic(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x01
    };

    const char *plaintext = "Hello, ChaCha20-Poly1305!";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[256];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);
    assert(ct_len == pt_len + CHACHA_POLY_TAG_LEN);

    unsigned char pt_out[256];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == pt_len);
    assert(memcmp(pt_out, plaintext, pt_len) == 0);

    printf("  PASS: test_roundtrip_basic\n");
}

static void test_roundtrip_empty_plaintext(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    unsigned char ct[64];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt(NULL, 0, key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);
    assert(ct_len == CHACHA_POLY_TAG_LEN);

    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == 0);

    printf("  PASS: test_roundtrip_empty_plaintext\n");
}

static void test_associated_data_integrity(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    const char *ad = "associated-data-12345";
    const char *plaintext = "secret payload";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[128];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce,
                                 (const unsigned char *)ad, strlen(ad),
                                 ct, &ct_len);
    assert(rc == 0);

    unsigned char pt_out[128];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce,
                             (const unsigned char *)ad, strlen(ad),
                             pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == pt_len);
    assert(memcmp(pt_out, plaintext, pt_len) == 0);

    /* Tamper with AD during decrypt — should fail */
    const char *bad_ad = "associated-data-XXXXX";
    size_t bad_pt_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce,
                             (const unsigned char *)bad_ad, strlen(bad_ad),
                             pt_out, &bad_pt_len);
    assert(rc == -1);

    printf("  PASS: test_associated_data_integrity\n");
}

static void test_tag_tamper_detection(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    const char *plaintext = "tamper me";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[128];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);

    /* Flip one bit in the tag */
    ct[ct_len - 1] ^= 0x01;

    unsigned char pt_out[128];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == -1);

    printf("  PASS: test_tag_tamper_detection\n");
}

static void test_wrong_key_rejection(void) {
    unsigned char key1[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char key2[CHACHA_POLY_KEY_LEN] = {1};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    const char *plaintext = "key mismatch";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[128];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key1, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);

    unsigned char pt_out[128];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key2, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == -1);

    printf("  PASS: test_wrong_key_rejection\n");
}

static void test_wrong_nonce_rejection(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce1[CHACHA_POLY_NONCE_LEN] = {0};
    unsigned char nonce2[CHACHA_POLY_NONCE_LEN] = {1};

    const char *plaintext = "nonce mismatch";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[128];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce1, NULL, 0, ct, &ct_len);
    assert(rc == 0);

    unsigned char pt_out[128];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce2, NULL, 0, pt_out, &pt_out_len);
    assert(rc == -1);

    printf("  PASS: test_wrong_nonce_rejection\n");
}

static void test_ciphertext_not_plaintext(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0x42};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    const char *plaintext = "AAAAAAAAAAAAAAAA";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[64];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);

    /* Ciphertext portion should differ from plaintext */
    assert(memcmp(ct, plaintext, pt_len) != 0);

    printf("  PASS: test_ciphertext_not_plaintext\n");
}

static void test_large_plaintext(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    size_t pt_len = 8192;
    unsigned char *plaintext = calloc(1, pt_len);
    assert(plaintext);
    memset(plaintext, 0xAB, pt_len);

    unsigned char *ct = malloc(pt_len + CHACHA_POLY_TAG_LEN);
    assert(ct);
    size_t ct_len = 0;

    int rc = chacha_poly_encrypt(plaintext, pt_len, key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);
    assert(ct_len == pt_len + CHACHA_POLY_TAG_LEN);

    unsigned char *pt_out = malloc(pt_len);
    assert(pt_out);
    size_t pt_out_len = 0;

    rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == pt_len);
    assert(memcmp(pt_out, plaintext, pt_len) == 0);

    free(plaintext);
    free(ct);
    free(pt_out);

    printf("  PASS: test_large_plaintext\n");
}

static void test_decrypt_too_short(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    /* Ciphertext shorter than tag length */
    unsigned char ct[8] = {0};
    unsigned char pt_out[8];
    size_t pt_out_len = 0;

    int rc = chacha_poly_decrypt(ct, 8, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == -1);

    printf("  PASS: test_decrypt_too_short\n");
}

int main(void) {
    printf("=== test_crypto: ChaCha20-Poly1305 ===\n");

    test_roundtrip_basic();
    test_roundtrip_empty_plaintext();
    test_associated_data_integrity();
    test_tag_tamper_detection();
    test_wrong_key_rejection();
    test_wrong_nonce_rejection();
    test_ciphertext_not_plaintext();
    test_large_plaintext();
    test_decrypt_too_short();

    printf("=== test_crypto: ALL PASSED ===\n");
    return 0;
}
