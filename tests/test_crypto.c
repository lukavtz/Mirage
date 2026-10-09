/*
 * test_crypto.c — ChaCha20-Poly1305 AEAD tests
 *
 * Tests chacha_poly_encrypt / chacha_poly_decrypt for:
 *   - RFC 8439 §2.8.2 known-answer test (KAT)
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

/*
 * RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 known-answer test, truncated
 * to the 12-byte prefix of the RFC's 114-byte message ("Ladies and G").
 * Inputs from the RFC vector: key 0x80..0x9f, nonce
 * 07:00:00:00:40:41:42:43:44:45:46:47 (32-bit fixed-common part 7,
 * IV "@ABCDEFG"), aad 50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7.
 * The ciphertext prefix is the first 12 bytes of the RFC ciphertext
 * (d3:1a:8d:34:64:8e:60:db:7b:86:af:bc...). The tag over only the
 * truncated message differs from the RFC's full-message tag, so the
 * expected tag below was verified byte-for-byte against Go's
 * x/crypto chacha20poly1305 (the panel's implementation).
 */
static void test_rfc8439_kat(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN];
    unsigned char nonce[CHACHA_POLY_NONCE_LEN];
    static const unsigned char aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x80 + i);   /* 0x80..0x9f */
    nonce[0] = 0x07; nonce[1] = 0x00; nonce[2] = 0x00; nonce[3] = 0x00;
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (unsigned char)(0x40 + i); /* 0x40..0x47 */

    const char *plaintext = "Ladies and G";
    size_t pt_len = strlen(plaintext);        /* 12 */

    /* first 12 bytes of the RFC §2.8.2 ciphertext */
    static const unsigned char expected_ct[12] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc
    };
    /* Poly1305 tag for aad(12)||pad||ct(12)||pad||le64(12)||le64(12).
     * Verified byte-for-byte against Go x/crypto chacha20poly1305
     * (the panel's implementation) — see test_interop_gen.c. */
    static const unsigned char expected_tag[16] = {
        0xe5, 0x16, 0x43, 0x6d, 0xf5, 0x9b, 0xdf, 0x1f,
        0x04, 0xff, 0x6e, 0x44, 0x73, 0x48, 0x96, 0xed
    };

    unsigned char out[64];
    size_t out_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                                 key, nonce, aad, sizeof(aad),
                                 out, &out_len);
    assert(rc == 0);
    assert(out_len == pt_len + CHACHA_POLY_TAG_LEN);
    if (memcmp(out, expected_ct, pt_len) != 0) {
        printf("  KAT ct mismatch: got ");
        for (size_t i = 0; i < pt_len; i++) printf("%02x", out[i]);
        printf("\n               want d31a8d34648e60db7b86afbc\n");
        assert(!"RFC 8439 KAT ciphertext mismatch");
    }
    if (memcmp(out + pt_len, expected_tag, CHACHA_POLY_TAG_LEN) != 0) {
        printf("  KAT tag mismatch: got ");
        for (size_t i = 0; i < 16; i++) printf("%02x", out[pt_len + i]);
        printf("\n               want e516436df59bdf1f04ff6e44734896ed\n");
        assert(!"RFC 8439 KAT tag mismatch");
    }

    /* KAT decrypt side: verifies tag and recovers the plaintext */
    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(out, out_len, key, nonce,
                             aad, sizeof(aad), pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == pt_len);
    assert(memcmp(pt_out, plaintext, pt_len) == 0);

    printf("  PASS: test_rfc8439_kat\n");
}

static void test_roundtrip_basic(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN];
    unsigned char nonce[CHACHA_POLY_NONCE_LEN];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (unsigned char)(i * 7 + 1);
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (unsigned char)(i + 3);

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
    int rc = chacha_poly_encrypt((const unsigned char *)"", 0,
                                 key, nonce, NULL, 0, ct, &ct_len);
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

    const char *pt = "data";
    const char *ad = "header";

    unsigned char ct[64];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt((const unsigned char *)pt, 4,
                                 key, nonce,
                                 (const unsigned char *)ad, 6,
                                 ct, &ct_len);
    assert(rc == 0);

    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    /* decrypt with different AD → must fail */
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce,
                             (const unsigned char *)"header!", 7,
                             pt_out, &pt_out_len);
    assert(rc != 0);

    /* decrypt with correct AD → must succeed */
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce,
                             (const unsigned char *)ad, 6,
                             pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == 4);
    assert(memcmp(pt_out, pt, 4) == 0);

    printf("  PASS: test_associated_data_integrity\n");
}

static void test_tag_tamper_detection(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {1};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {2};

    const char *plaintext = "tamper test";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[64];
    size_t ct_len = 0;
    chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                        key, nonce, NULL, 0, ct, &ct_len);
    assert(ct_len == pt_len + CHACHA_POLY_TAG_LEN);

    /* flip one bit in the tag */
    ct[ct_len - 1] ^= 1;

    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    int rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc != 0);

    printf("  PASS: test_tag_tamper_detection\n");
}

static void test_wrong_key_rejection(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {3};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {4};

    const char *plaintext = "secret message";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[64];
    size_t ct_len = 0;
    chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                        key, nonce, NULL, 0, ct, &ct_len);

    unsigned char wrong_key[CHACHA_POLY_KEY_LEN] = {5};
    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    int rc = chacha_poly_decrypt(ct, ct_len, wrong_key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc != 0);

    printf("  PASS: test_wrong_key_rejection\n");
}

static void test_wrong_nonce_rejection(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {6};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {7};

    const char *plaintext = "nonce test";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[64];
    size_t ct_len = 0;
    chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                        key, nonce, NULL, 0, ct, &ct_len);

    unsigned char wrong_nonce[CHACHA_POLY_NONCE_LEN] = {8};
    unsigned char pt_out[64];
    size_t pt_out_len = 0;
    int rc = chacha_poly_decrypt(ct, ct_len, key, wrong_nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc != 0);

    printf("  PASS: test_wrong_nonce_rejection\n");
}

static void test_ciphertext_not_plaintext(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};

    const char *plaintext = "0123456789abcdef";
    size_t pt_len = strlen(plaintext);

    unsigned char ct[64];
    size_t ct_len = 0;
    chacha_poly_encrypt((const unsigned char *)plaintext, pt_len,
                        key, nonce, NULL, 0, ct, &ct_len);

    /* ciphertext bytes must differ from plaintext bytes */
    int differs = 0;
    for (size_t i = 0; i < pt_len; i++) {
        if (ct[i] != (unsigned char)plaintext[i]) { differs = 1; break; }
    }
    assert(differs);

    printf("  PASS: test_ciphertext_not_plaintext\n");
}

static void test_large_plaintext(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {9};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {10};

    unsigned char plaintext[4096];
    for (size_t i = 0; i < sizeof(plaintext); i++)
        plaintext[i] = (unsigned char)(i % 251);

    unsigned char ct[4096 + 16];
    size_t ct_len = 0;
    int rc = chacha_poly_encrypt(plaintext, sizeof(plaintext),
                                 key, nonce, NULL, 0, ct, &ct_len);
    assert(rc == 0);
    assert(ct_len == sizeof(plaintext) + CHACHA_POLY_TAG_LEN);

    unsigned char pt_out[4096];
    size_t pt_out_len = 0;
    rc = chacha_poly_decrypt(ct, ct_len, key, nonce, NULL, 0, pt_out, &pt_out_len);
    assert(rc == 0);
    assert(pt_out_len == sizeof(plaintext));
    assert(memcmp(pt_out, plaintext, sizeof(plaintext)) == 0);

    printf("  PASS: test_large_plaintext\n");
}

static void test_decrypt_too_short(void) {
    unsigned char key[CHACHA_POLY_KEY_LEN] = {0};
    unsigned char nonce[CHACHA_POLY_NONCE_LEN] = {0};
    unsigned char ct[8] = {0};
    unsigned char pt_out[16];
    size_t pt_out_len = 0;
    int rc = chacha_poly_decrypt(ct, sizeof(ct), key, nonce, NULL, 0,
                                 pt_out, &pt_out_len);
    assert(rc != 0);

    printf("  PASS: test_decrypt_too_short\n");
}

int main(void) {
    printf("test_crypto:\n");
    test_rfc8439_kat();
    test_roundtrip_basic();
    test_roundtrip_empty_plaintext();
    test_associated_data_integrity();
    test_tag_tamper_detection();
    test_wrong_key_rejection();
    test_wrong_nonce_rejection();
    test_ciphertext_not_plaintext();
    test_large_plaintext();
    test_decrypt_too_short();
    printf("  all tests passed\n");
    return 0;
}
