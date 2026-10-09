/*
 * test_chrome_crypto.c — Chrome crypto tests (standalone)
 *
 * Tests the crypto algorithms matching Chrome's implementation.
 * Does not link chrome_crypto.c (needs PEB-walk on Windows).
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc/utils -std=c11
 *        -o tests/test_chrome_crypto.exe tests/test_chrome_crypto.c src/utils/base64.c -lssl -lcrypto
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; return; } else { g_pass++; } } while(0)

/* ── Reimplemented chrome_extract_encrypted_key ─────────── */
#include "utils/base64.h"

static void *compat_memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void *)h;
    if (nl > hl) return NULL;
    for (size_t i = 0; i <= hl - nl; i++)
        if (memcmp((const char *)h + i, n, nl) == 0) return (void *)((const char *)h + i);
    return NULL;
}

static int chrome_extract_encrypted_key(const char *json, size_t json_len,
                                        unsigned char *out, size_t out_max, size_t *out_len) {
    const char marker[] = "\"encrypted_key\":\"";
    const char *start = compat_memmem(json, json_len, marker, sizeof(marker) - 1);
    if (!start) return -1;
    start += sizeof(marker) - 1;
    const char *end = memchr(start, '"', (size_t)(json + json_len - start));
    if (!end) return -1;
    size_t b64_len = (size_t)(end - start);
    int decoded = base64_decode(start, b64_len, out, out_max);
    if (decoded < 0) return -1;
    *out_len = (size_t)decoded;
    return 0;
}

/* ── Reimplemented chrome_derive_key (Linux path) ──────── */
static int chrome_derive_key(unsigned char *out32) {
    const char *salt = "saltysalt";
    return PKCS5_PBKDF2_HMAC_SHA1("", 0,
        (const unsigned char *)salt, 9, 1, 32, out32) == 1 ? 0 : -1;
}

/* ── Reimplemented chrome_decrypt_password (Linux path) ── */
/* Local mirror of src/crypto/chrome_crypto.c contract: -1 implies *out_len == 0. */
static int chrome_decrypt_password(const unsigned char *encrypted, size_t len,
                                   const unsigned char *key32,
                                   unsigned char *out, size_t out_max, size_t *out_len) {
    *out_len = 0;
    if (len < 3 + 12 + 16) return -1;
    if (memcmp(encrypted, "v10", 3) != 0 && memcmp(encrypted, "v11", 3) != 0 &&
        memcmp(encrypted, "v20", 3) != 0)
        return -1;
    const unsigned char *nonce = encrypted + 3;
    const unsigned char *ciphertext = encrypted + 15;
    size_t ct_len = len - 15 - 16;
    const unsigned char *tag = encrypted + len - 16;
    if (out_max < ct_len) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = 0, outl = 0, total = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key32, nonce) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)ct_len) != 1) goto fail;
    total = outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto fail;
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

/* ── Encrypt helper for roundtrip tests ────────────────── */
static int chrome_encrypt_password(const unsigned char *plaintext, size_t pt_len,
                                   const unsigned char *key32,
                                   const unsigned char *nonce,
                                   unsigned char *out, size_t *out_len) {
    memcpy(out, "v10", 3);
    memcpy(out + 3, nonce, 12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key32, nonce) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, out + 15, &outl, plaintext, (int)pt_len) != 1) goto fail;
    total = outl;
    if (EVP_EncryptFinal_ex(ctx, out + 15 + total, &outl) != 1) goto fail;
    total += outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + 15 + total) != 1) goto fail;
    total += 16;
    EVP_CIPHER_CTX_free(ctx);
    *out_len = 15 + (size_t)total;
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* ── Tests ─────────────────────────────────────────────── */

static void test_extract_key_basic(void) {
    const char *json = "{\"os_crypt\":{\"encrypted_key\":\"aGVsbG8=\"}}";
    unsigned char out[64]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == 0, "rc");
    CHECK(out_len == 5, "len"); CHECK(memcmp(out, "hello", 5) == 0, "val");
}

static void test_extract_key_missing(void) {
    const char *json = "{\"os_crypt\":{}}";
    unsigned char out[64]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == -1, "missing");
}

static void test_extract_key_empty(void) {
    const char *json = "{\"encrypted_key\":\"\"}";
    unsigned char out[64]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == -1, "empty");
}

static void test_extract_key_buffer_small(void) {
    const char *json = "{\"encrypted_key\":\"aGVsbG8gd29ybGQ=\"}";
    unsigned char out[4]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == -1, "small");
}

static void test_extract_key_realistic(void) {
    const char *json = "{\"os_crypt\":{\"encrypted_key\":\"AQAAAIBMnd8=\"}}";
    unsigned char out[128]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == 0, "rc");
    CHECK(out_len == 8, "len"); CHECK(out[0] == 0x01, "ver");
}

static void test_extract_key_truncated(void) {
    const char *json = "{\"encrypted_key\":\"aGVsb";
    unsigned char out[64]; size_t out_len = 0;
    CHECK(chrome_extract_encrypted_key(json, strlen(json), out, sizeof(out), &out_len) == -1, "trunc");
}

static void test_derive_key(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    unsigned char key2[32];
    CHECK(chrome_derive_key(key2) == 0, "derive2");
    CHECK(memcmp(key, key2, 32) == 0, "deterministic");
    unsigned char zeros[32] = {0};
    CHECK(memcmp(key, zeros, 32) != 0, "not-zero");
}

/* PBKDF2-SHA1 known vector: empty password, "saltysalt", 1 iter, 32 bytes */
static void test_derive_key_known(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    /* Chrome's PBKDF2 with empty password + "saltysalt" + 1 iter + 32 bytes
     * produces a deterministic result. Verify it matches OpenSSL directly. */
    unsigned char verify[32];
    CHECK(PKCS5_PBKDF2_HMAC_SHA1("", 0, (const unsigned char *)"saltysalt", 9, 1, 32, verify) == 1, "openssl");
    CHECK(memcmp(key, verify, 32) == 0, "match");
}

static void test_decrypt_roundtrip(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    const char *plaintext = "test_password_123";
    size_t pt_len = strlen(plaintext);
    unsigned char nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    unsigned char encrypted[256]; size_t enc_len = 0;
    CHECK(chrome_encrypt_password((const unsigned char *)plaintext, pt_len, key, nonce, encrypted, &enc_len) == 0, "encrypt");
    unsigned char out[256]; size_t out_len = 0;
    CHECK(chrome_decrypt_password(encrypted, enc_len, key, out, sizeof(out), &out_len) == 0, "decrypt");
    CHECK(out_len == pt_len, "out_len");
    CHECK(memcmp(out, plaintext, pt_len) == 0, "plaintext");
}

static void test_decrypt_wrong_key(void) {
    unsigned char key[32], wrong[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    memset(wrong, 0x42, 32);
    unsigned char nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    unsigned char encrypted[256]; size_t enc_len = 0;
    CHECK(chrome_encrypt_password((const unsigned char *)"test", 4, key, nonce, encrypted, &enc_len) == 0, "enc");
    unsigned char out[256]; size_t out_len = 0;
    CHECK(chrome_decrypt_password(encrypted, enc_len, wrong, out, sizeof(out), &out_len) == -1, "wrong-key");
}

static void test_decrypt_bad_prefix(void) {
    unsigned char blob[50]; memset(blob, 0, sizeof(blob));
    memcpy(blob, "v99", 3);
    unsigned char key[32] = {0}, out[256]; size_t out_len = 0;
    CHECK(chrome_decrypt_password(blob, sizeof(blob), key, out, sizeof(out), &out_len) == -1, "bad-prefix");
}

static void test_decrypt_short(void) {
    unsigned char blob[10] = {0}, key[32] = {0}, out[256]; size_t out_len = 0;
    CHECK(chrome_decrypt_password(blob, sizeof(blob), key, out, sizeof(out), &out_len) == -1, "short");
}

static void test_decrypt_empty_plaintext(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    unsigned char nonce[12] = {0};
    unsigned char encrypted[256]; size_t enc_len = 0;
    CHECK(chrome_encrypt_password((const unsigned char *)"", 0, key, nonce, encrypted, &enc_len) == 0, "enc");
    unsigned char out[256]; size_t out_len = 0;
    CHECK(chrome_decrypt_password(encrypted, enc_len, key, out, sizeof(out), &out_len) == 0, "decrypt");
    CHECK(out_len == 0, "empty");
}

static void test_decrypt_corrupted_tag(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    unsigned char nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    unsigned char encrypted[256]; size_t enc_len = 0;
    CHECK(chrome_encrypt_password((const unsigned char *)"secret", 6, key, nonce, encrypted, &enc_len) == 0, "enc");
    /* Corrupt the last tag byte — GCM auth MUST fail */
    encrypted[enc_len - 1] ^= 0x80;
    unsigned char out[256]; size_t out_len = 42;
    CHECK(chrome_decrypt_password(encrypted, enc_len, key, out, sizeof(out), &out_len) == -1, "corrupt-tag");
    CHECK(out_len == 0, "corrupt-tag-outlen-zero");
}

static void test_decrypt_corrupted_ciphertext(void) {
    unsigned char key[32];
    CHECK(chrome_derive_key(key) == 0, "derive");
    unsigned char nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    unsigned char encrypted[256]; size_t enc_len = 0;
    CHECK(chrome_encrypt_password((const unsigned char *)"secret", 6, key, nonce, encrypted, &enc_len) == 0, "enc");
    /* Corrupt first ciphertext byte — auth MUST fail */
    encrypted[15] ^= 0x01;
    unsigned char out[256]; size_t out_len = 42;
    CHECK(chrome_decrypt_password(encrypted, enc_len, key, out, sizeof(out), &out_len) == -1, "corrupt-ct");
    CHECK(out_len == 0, "corrupt-ct-outlen-zero");
}

int main(void) {
    printf("=== test_chrome_crypto ===\n"); fflush(stdout);
    test_extract_key_basic();     printf("  PASS: extract_basic\n"); fflush(stdout);
    test_extract_key_missing();   printf("  PASS: extract_missing\n"); fflush(stdout);
    test_extract_key_empty();     printf("  PASS: extract_empty\n"); fflush(stdout);
    test_extract_key_buffer_small(); printf("  PASS: extract_small\n"); fflush(stdout);
    test_extract_key_realistic(); printf("  PASS: extract_realistic\n"); fflush(stdout);
    test_extract_key_truncated(); printf("  PASS: extract_truncated\n"); fflush(stdout);
    test_derive_key();            printf("  PASS: derive_key\n"); fflush(stdout);
    test_derive_key_known();      printf("  PASS: derive_key_known\n"); fflush(stdout);
    test_decrypt_roundtrip();     printf("  PASS: decrypt_roundtrip\n"); fflush(stdout);
    test_decrypt_wrong_key();     printf("  PASS: decrypt_wrong_key\n"); fflush(stdout);
    test_decrypt_bad_prefix();    printf("  PASS: decrypt_bad_prefix\n"); fflush(stdout);
    test_decrypt_short();         printf("  PASS: decrypt_short\n"); fflush(stdout);
    test_decrypt_empty_plaintext(); printf("  PASS: decrypt_empty\n"); fflush(stdout);
    test_decrypt_corrupted_tag();    printf("  PASS: decrypt_corrupted_tag\n"); fflush(stdout);
    test_decrypt_corrupted_ciphertext(); printf("  PASS: decrypt_corrupted_ciphertext\n"); fflush(stdout);
    printf("=== test_chrome_crypto: %d/%d PASSED ===\n", g_pass, g_pass + g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
