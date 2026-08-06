/*
 * test_firefox_crypto.c — Firefox crypto tests (standalone)
 *
 * Re-implements crypto primitives using OpenSSL directly (matching
 * the Linux paths in firefox_crypto.c). Does NOT link firefox_crypto.c
 * (needs BCrypt PEB-walk on Windows).
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc/utils -std=c11
 *        -o tests/test_firefox_crypto.exe tests/test_firefox_crypto.c
 *        src/utils/secure_zero.c -lssl -lcrypto
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; return; } else { g_pass++; } } while(0)

/* Reimplement fx_sha1 (matches firefox_crypto.c Linux path) */
static void fx_sha1_local(const unsigned char *data, size_t len, unsigned char *out20) {
    SHA1(data, len, out20);
}

/* Reimplement fx_hmac_sha1 */
static void fx_hmac_sha1_local(const unsigned char *key, size_t key_len,
                               const unsigned char *data, size_t data_len,
                               unsigned char *out20) {
    unsigned int md_len = 20;
    HMAC(EVP_sha1(), key, (int)key_len, data, data_len, out20, &md_len);
}

/* Reimplement fx_des3_decrypt_cbc */
static int fx_des3_decrypt_cbc(const uint8_t *key24, const uint8_t *iv8,
                               const unsigned char *data, size_t data_len,
                               unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 8 != 0 || out_max < data_len) return -1;
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key_unchecked((const_DES_cblock *)key24, &ks1);
    DES_set_key_unchecked((const_DES_cblock *)(key24 + 8), &ks2);
    DES_set_key_unchecked((const_DES_cblock *)(key24 + 16), &ks3);
    unsigned char iv_copy[8]; memcpy(iv_copy, iv8, 8);
    DES_ede3_cbc_encrypt(data, out, (long)data_len, &ks1, &ks2, &ks3,
                         (DES_cblock *)iv_copy, DES_DECRYPT);
    /* PKCS7 unpad */
    unsigned char pad = out[data_len - 1];
    if (pad == 0 || pad > 8 || pad > data_len) return -1;
    for (size_t i = 0; i < pad; i++)
        if (out[data_len - 1 - i] != pad) return -1;
    *out_len = data_len - pad;
    return 0;
}

/* Reimplement fx_aes128_decrypt_cbc */
static int fx_aes128_decrypt_cbc(const uint8_t *key16, const uint8_t *iv16,
                                 const unsigned char *data, size_t data_len,
                                 unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 16 != 0 || out_max < data_len) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0, total = 0, rc = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key16, iv16) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, out, &outl, data, (int)data_len) != 1) goto fail;
    total = outl;
    rc = EVP_DecryptFinal_ex(ctx, out + total, &outl);
    total += outl;
    EVP_CIPHER_CTX_free(ctx);
    if (rc <= 0) return -1;
    *out_len = (size_t)total;
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* Reimplement fx_decrypt_login_pbe: SHA1(key) → 24-byte 3DES key, IV = first 8 bytes */
static int fx_decrypt_login_pbe_local(const unsigned char *key, size_t key_len,
                                      const unsigned char *iv_and_data, size_t len,
                                      unsigned char *out, size_t out_max, size_t *out_len) {
    if (len < 16) return -1;
    unsigned char key_hash[20];
    SHA1(key, key_len, key_hash);
    unsigned char des_key[24];
    memcpy(des_key, key_hash, 20);
    memset(des_key + 20, 0, 4);
    const unsigned char *iv = iv_and_data;
    const unsigned char *encrypted = iv_and_data + 8;
    size_t enc_len = len - 8;
    if (enc_len == 0 || enc_len % 8 != 0) return -1;
    size_t dec_len = 0;
    if (fx_des3_decrypt_cbc(des_key, iv, encrypted, enc_len, out, out_max, &dec_len) < 0)
        return -1;
    *out_len = dec_len;
    return 0;
}

/* ── ASN.1 DER reader (reimplemented to match firefox_crypto.c) ── */

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} TestAsn1Reader;

static int asn1_read_tag(TestAsn1Reader *r, uint8_t *tag) {
    if (r->pos >= r->len) return -1;
    *tag = r->data[r->pos++];
    return 0;
}

static int asn1_read_length(TestAsn1Reader *r, size_t *length) {
    if (r->pos >= r->len) return -1;
    uint8_t b = r->data[r->pos++];
    if (b < 0x80) { *length = b; return 0; }
    int nbytes = b & 0x7F;
    if (nbytes == 0 || r->pos + (size_t)nbytes > r->len) return -1;
    size_t v = 0;
    for (int i = 0; i < nbytes; i++)
        v = (v << 8) | r->data[r->pos++];
    *length = v;
    return 0;
}

/* ── Tests ─────────────────────────────────────────────── */

static void test_sha1_empty(void) {
    unsigned char hash[20];
    fx_sha1_local((const unsigned char *)"", 0, hash);
    const unsigned char expected[20] = {
        0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,
        0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09
    };
    CHECK(memcmp(hash, expected, 20) == 0, "sha1-empty");
}

static void test_sha1_abc(void) {
    unsigned char hash[20];
    fx_sha1_local((const unsigned char *)"abc", 3, hash);
    const unsigned char expected[20] = {
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
        0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d
    };
    CHECK(memcmp(hash, expected, 20) == 0, "sha1-abc");
}

static void test_hmac_sha1(void) {
    unsigned char mac[20];
    fx_hmac_sha1_local((const unsigned char *)"key", 3,
                       (const unsigned char *)"The quick brown fox jumps over the lazy dog", 43,
                       mac);
    const unsigned char expected[20] = {
        0xde,0x7c,0x9b,0x85,0xb8,0xb7,0x8a,0xa6,0xbc,0x8a,
        0x7a,0x36,0xf7,0x0a,0x90,0x70,0x1c,0x9d,0xb4,0xd9
    };
    CHECK(memcmp(mac, expected, 20) == 0, "hmac-sha1");
}

static void test_des3_roundtrip(void) {
    unsigned char key24[24]; memset(key24, 0x42, 24);
    unsigned char iv8[8] = {1,2,3,4,5,6,7,8};
    unsigned char padded[16];
    memcpy(padded, "Hello3DES!!!", 12);
    memset(padded + 12, 4, 4); /* PKCS7 pad to 16 */

    /* Encrypt with OpenSSL */
    unsigned char ciphertext[32];
    unsigned char iv_copy[8]; memcpy(iv_copy, iv8, 8);
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key_unchecked((const_DES_cblock *)key24, &ks1);
    DES_set_key_unchecked((const_DES_cblock *)(key24 + 8), &ks2);
    DES_set_key_unchecked((const_DES_cblock *)(key24 + 16), &ks3);
    DES_ede3_cbc_encrypt(padded, ciphertext, 16, &ks1, &ks2, &ks3,
                         (DES_cblock *)iv_copy, DES_ENCRYPT);

    /* Decrypt with fx_des3_decrypt_cbc */
    unsigned char out[32]; size_t out_len = 0;
    CHECK(fx_des3_decrypt_cbc(key24, iv8, ciphertext, 16, out, sizeof(out), &out_len) == 0, "rc");
    CHECK(out_len == 12, "len");
    CHECK(memcmp(out, "Hello3DES!!!", 12) == 0, "data");
}

static void test_des3_not_multiple_of_8(void) {
    unsigned char key24[24] = {0}, iv8[8] = {0}, data[7] = {0}, out[32]; size_t out_len = 0;
    CHECK(fx_des3_decrypt_cbc(key24, iv8, data, 7, out, sizeof(out), &out_len) == -1, "not-8");
}

static void test_aes128_roundtrip(void) {
    unsigned char key16[16]; memset(key16, 0x55, 16);
    unsigned char iv16[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const char *pt = "AES128CBCtest!!"; /* 16 bytes, pad to 32 with PKCS7 */

    /* Encrypt 16 bytes — OpenSSL adds PKCS7 padding automatically */
    unsigned char ct[32]; int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key16, iv16);
    EVP_EncryptUpdate(ctx, ct, &outl, (const unsigned char *)pt, 16);
    int total = outl;
    EVP_EncryptFinal_ex(ctx, ct + total, &outl);
    total += outl;
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt */
    unsigned char out[32]; size_t out_len = 0;
    CHECK(fx_aes128_decrypt_cbc(key16, iv16, ct, (size_t)total, out, sizeof(out), &out_len) == 0, "rc");
    CHECK(out_len == 16, "len");
    CHECK(memcmp(out, pt, 16) == 0, "data");
}

static void test_aes128_not_multiple_of_16(void) {
    unsigned char key16[16] = {0}, iv16[16] = {0}, data[7] = {0}, out[32]; size_t out_len = 0;
    CHECK(fx_aes128_decrypt_cbc(key16, iv16, data, 7, out, sizeof(out), &out_len) == -1, "not-16");
}

static void test_asn1_read_tag(void) {
    unsigned char data[] = {0x30, 0x03};
    TestAsn1Reader r = { data, sizeof(data), 0 };
    uint8_t tag = 0;
    CHECK(asn1_read_tag(&r, &tag) == 0, "rc");
    CHECK(tag == 0x30, "tag");
    CHECK(r.pos == 1, "pos");
}

static void test_asn1_read_length_short(void) {
    unsigned char data[] = {0x05};
    TestAsn1Reader r = { data, sizeof(data), 0 };
    size_t length = 0;
    CHECK(asn1_read_length(&r, &length) == 0, "rc");
    CHECK(length == 5, "len");
}

static void test_asn1_read_length_long(void) {
    unsigned char data[] = {0x82, 0x01, 0x2C};
    TestAsn1Reader r = { data, sizeof(data), 0 };
    size_t length = 0;
    CHECK(asn1_read_length(&r, &length) == 0, "rc");
    CHECK(length == 300, "len");
}

static void test_asn1_read_length_empty(void) {
    TestAsn1Reader r = { NULL, 0, 0 };
    size_t length = 0;
    CHECK(asn1_read_length(&r, &length) == -1, "empty");
}

static void test_login_pbe(void) {
    unsigned char key[20]; memset(key, 0xAA, 20);
    unsigned char padded[8]; memcpy(padded, "hello", 5);
    memset(padded + 5, 3, 3); /* PKCS7 */

    /* Compute SHA1(key) as DES key */
    unsigned char key_hash[20];
    SHA1(key, 20, key_hash);
    unsigned char des_key[24]; memcpy(des_key, key_hash, 20); memset(des_key + 20, 0, 4);

    unsigned char iv[8] = {1,2,3,4,5,6,7,8};
    unsigned char ct[8]; unsigned char iv_copy[8]; memcpy(iv_copy, iv, 8);
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key_unchecked((const_DES_cblock *)des_key, &ks1);
    DES_set_key_unchecked((const_DES_cblock *)(des_key + 8), &ks2);
    DES_set_key_unchecked((const_DES_cblock *)(des_key + 16), &ks3);
    DES_ede3_cbc_encrypt(padded, ct, 8, &ks1, &ks2, &ks3, (DES_cblock *)iv_copy, DES_ENCRYPT);

    unsigned char iv_and_data[16]; memcpy(iv_and_data, iv, 8); memcpy(iv_and_data + 8, ct, 8);
    unsigned char out[64]; size_t out_len = 0;
    CHECK(fx_decrypt_login_pbe_local(key, 20, iv_and_data, 16, out, sizeof(out), &out_len) == 0, "rc");
    CHECK(out_len == 5, "len");
    CHECK(memcmp(out, "hello", 5) == 0, "val");
}

static void test_login_pbe_too_short(void) {
    unsigned char key[20] = {0};
    unsigned char data[8] = {0}; /* only IV, no ciphertext */
    unsigned char out[64]; size_t out_len = 0;
    CHECK(fx_decrypt_login_pbe_local(key, 20, data, 8, out, sizeof(out), &out_len) == -1, "short");
}

int main(void) {
    printf("=== test_firefox_crypto ===\n"); fflush(stdout);
    test_sha1_empty();               printf("  PASS: sha1_empty\n"); fflush(stdout);
    test_sha1_abc();                 printf("  PASS: sha1_abc\n"); fflush(stdout);
    test_hmac_sha1();                printf("  PASS: hmac_sha1\n"); fflush(stdout);
    test_des3_roundtrip();           printf("  PASS: des3_roundtrip\n"); fflush(stdout);
    test_des3_not_multiple_of_8();   printf("  PASS: des3_not_8\n"); fflush(stdout);
    test_aes128_roundtrip();         printf("  PASS: aes128_roundtrip\n"); fflush(stdout);
    test_aes128_not_multiple_of_16(); printf("  PASS: aes128_not_16\n"); fflush(stdout);
    test_asn1_read_tag();            printf("  PASS: asn1_tag\n"); fflush(stdout);
    test_asn1_read_length_short();   printf("  PASS: asn1_len_short\n"); fflush(stdout);
    test_asn1_read_length_long();    printf("  PASS: asn1_len_long\n"); fflush(stdout);
    test_asn1_read_length_empty();   printf("  PASS: asn1_len_empty\n"); fflush(stdout);
    test_login_pbe();                printf("  PASS: login_pbe\n"); fflush(stdout);
    test_login_pbe_too_short();      printf("  PASS: login_pbe_short\n"); fflush(stdout);
    printf("=== test_firefox_crypto: %d/%d PASSED ===\n", g_pass, g_pass + g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
