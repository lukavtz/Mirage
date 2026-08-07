/*
 * test_archive_crypt.c — Archive encryption tests (standalone)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "chacha_poly.h"
#include "secure_zero.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; return; } else { g_pass++; } } while(0)

#define ARCHIVE_SALT_LEN 16
#define ARCHIVE_HEADER_LEN (12 + ARCHIVE_SALT_LEN)

static int archive_derive_key(const unsigned char *password, size_t password_len,
                              const unsigned char *salt, size_t salt_len,
                              unsigned char out_key[32]) {
    int rc = PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len,
                                salt, (int)salt_len,
                                1000, EVP_sha256(), 32, out_key);
    return (rc == 1) ? 0 : -1;
}

static int archive_encrypt(const unsigned char *pt, size_t pt_len,
                           unsigned char *out, size_t *out_len) {
    unsigned char nonce[CHACHA_POLY_NONCE_LEN], salt[ARCHIVE_SALT_LEN];
    if (RAND_bytes(nonce, CHACHA_POLY_NONCE_LEN) != 1) return -1;
    if (RAND_bytes(salt, ARCHIVE_SALT_LEN) != 1) return -1;
    const unsigned char password[] = "test_seed";
    unsigned char derived_key[32];
    if (archive_derive_key(password, sizeof(password) - 1, salt, ARCHIVE_SALT_LEN, derived_key) < 0)
        return -1;
    size_t total = ARCHIVE_HEADER_LEN + pt_len + CHACHA_POLY_TAG_LEN;
    if (*out_len < total) { mirage_secure_zero(derived_key, 32); return -1; }
    memcpy(out, nonce, CHACHA_POLY_NONCE_LEN);
    memcpy(out + CHACHA_POLY_NONCE_LEN, salt, ARCHIVE_SALT_LEN);
    size_t enc_len = 0;
    int rc = chacha_poly_encrypt(pt, pt_len, derived_key, nonce, NULL, 0,
                                 out + ARCHIVE_HEADER_LEN, &enc_len);
    mirage_secure_zero(derived_key, 32);
    if (rc < 0) return -1;
    *out_len = ARCHIVE_HEADER_LEN + enc_len;
    return 0;
}

static int archive_decrypt(const unsigned char *ct, size_t ct_len,
                           unsigned char *out, size_t *out_len) {
    if (ct_len < ARCHIVE_HEADER_LEN + CHACHA_POLY_TAG_LEN) return -1;
    unsigned char nonce[CHACHA_POLY_NONCE_LEN], salt[ARCHIVE_SALT_LEN];
    memcpy(nonce, ct, CHACHA_POLY_NONCE_LEN);
    memcpy(salt, ct + CHACHA_POLY_NONCE_LEN, ARCHIVE_SALT_LEN);
    const unsigned char password[] = "test_seed";
    unsigned char derived_key[32];
    if (archive_derive_key(password, sizeof(password) - 1, salt, ARCHIVE_SALT_LEN, derived_key) < 0)
        return -1;
    const unsigned char *ciphertext = ct + ARCHIVE_HEADER_LEN;
    size_t ciphertext_len = ct_len - ARCHIVE_HEADER_LEN;
    int rc = chacha_poly_decrypt(ciphertext, ciphertext_len, derived_key, nonce,
                                 NULL, 0, out, out_len);
    mirage_secure_zero(derived_key, 32);
    return rc;
}

static void test_derive_key_deterministic(void) {
    const unsigned char pw[] = "test_password";
    const unsigned char salt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char key1[32], key2[32];
    CHECK(archive_derive_key(pw, sizeof(pw)-1, salt, 16, key1) == 0, "d1");
    CHECK(archive_derive_key(pw, sizeof(pw)-1, salt, 16, key2) == 0, "d2");
    CHECK(memcmp(key1, key2, 32) == 0, "deterministic");
    unsigned char zeros[32] = {0};
    CHECK(memcmp(key1, zeros, 32) != 0, "not-zero");
}

static void test_derive_key_different_salt(void) {
    const unsigned char pw[] = "test";
    unsigned char salt1[16] = {0}, salt2[16];
    memset(salt2, 0xFF, 16);
    unsigned char key1[32], key2[32];
    CHECK(archive_derive_key(pw, 4, salt1, 16, key1) == 0, "k1");
    CHECK(archive_derive_key(pw, 4, salt2, 16, key2) == 0, "k2");
    CHECK(memcmp(key1, key2, 32) != 0, "diff");
}

static void test_roundtrip(void) {
    const unsigned char pt[] = "Hello, archive encryption!";
    size_t pt_len = strlen((const char *)pt);
    unsigned char enc[512]; size_t enc_len = sizeof(enc);
    CHECK(archive_encrypt(pt, pt_len, enc, &enc_len) == 0, "enc");
    CHECK(enc_len == ARCHIVE_HEADER_LEN + pt_len + CHACHA_POLY_TAG_LEN, "enc-len");
    unsigned char dec[512]; size_t dec_len = sizeof(dec);
    CHECK(archive_decrypt(enc, enc_len, dec, &dec_len) == 0, "dec");
    CHECK(dec_len == pt_len, "dec-len");
    CHECK(memcmp(dec, pt, pt_len) == 0, "data");
}

static void test_empty(void) {
    unsigned char enc[256]; size_t enc_len = sizeof(enc);
    CHECK(archive_encrypt((const unsigned char *)"", 0, enc, &enc_len) == 0, "enc");
    CHECK(enc_len == ARCHIVE_HEADER_LEN + CHACHA_POLY_TAG_LEN, "len");
    unsigned char dec[256]; size_t dec_len = sizeof(dec);
    CHECK(archive_decrypt(enc, enc_len, dec, &dec_len) == 0, "dec");
    CHECK(dec_len == 0, "empty");
}

static void test_too_short(void) {
    unsigned char sd[10] = {0}, out[64]; size_t out_len = sizeof(out);
    CHECK(archive_decrypt(sd, sizeof(sd), out, &out_len) == -1, "short");
}

static void test_tampered(void) {
    const unsigned char pt[] = "tamper test";
    size_t pt_len = strlen((const char *)pt);
    unsigned char enc[256]; size_t enc_len = sizeof(enc);
    CHECK(archive_encrypt(pt, pt_len, enc, &enc_len) == 0, "enc");
    enc[ARCHIVE_HEADER_LEN + 1] ^= 0xFF;
    unsigned char dec[256]; size_t dec_len = sizeof(dec);
    CHECK(archive_decrypt(enc, enc_len, dec, &dec_len) == -1, "tampered");
}

static void test_tampered_nonce(void) {
    const unsigned char pt[] = "nonce tamper";
    size_t pt_len = strlen((const char *)pt);
    unsigned char enc[256]; size_t enc_len = sizeof(enc);
    CHECK(archive_encrypt(pt, pt_len, enc, &enc_len) == 0, "enc");
    enc[0] ^= 0xFF;
    unsigned char dec[256]; size_t dec_len = sizeof(dec);
    CHECK(archive_decrypt(enc, enc_len, dec, &dec_len) == -1, "nonce");
}

static void test_small_buf(void) {
    const unsigned char pt[] = "test";
    unsigned char enc[10]; size_t enc_len = sizeof(enc);
    CHECK(archive_encrypt(pt, 4, enc, &enc_len) == -1, "small");
}

static void test_nonces_unique(void) {
    const unsigned char pt[] = "same input";
    size_t pt_len = strlen((const char *)pt);
    unsigned char enc1[256], enc2[256];
    size_t len1 = sizeof(enc1), len2 = sizeof(enc2);
    CHECK(archive_encrypt(pt, pt_len, enc1, &len1) == 0, "e1");
    CHECK(archive_encrypt(pt, pt_len, enc2, &len2) == 0, "e2");
    CHECK(memcmp(enc1, enc2, CHACHA_POLY_NONCE_LEN) != 0, "nonce-diff");
    CHECK(memcmp(enc1 + CHACHA_POLY_NONCE_LEN, enc2 + CHACHA_POLY_NONCE_LEN, ARCHIVE_SALT_LEN) != 0, "salt-diff");
}

int main(void) {
    printf("=== test_archive_crypt ===\n"); fflush(stdout);
    test_derive_key_deterministic();  printf("  PASS: derive_deterministic\n"); fflush(stdout);
    test_derive_key_different_salt(); printf("  PASS: derive_diff_salt\n"); fflush(stdout);
    test_roundtrip();                 printf("  PASS: roundtrip\n"); fflush(stdout);
    test_empty();                     printf("  PASS: empty\n"); fflush(stdout);
    test_too_short();                 printf("  PASS: too_short\n"); fflush(stdout);
    test_tampered();                  printf("  PASS: tampered\n"); fflush(stdout);
    test_tampered_nonce();            printf("  PASS: tampered_nonce\n"); fflush(stdout);
    test_small_buf();                 printf("  PASS: small_buf\n"); fflush(stdout);
    test_nonces_unique();             printf("  PASS: nonces_unique\n"); fflush(stdout);
    printf("=== test_archive_crypt: %d/%d PASSED ===\n", g_pass, g_pass + g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
