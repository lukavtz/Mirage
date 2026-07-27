/*
 * dpapi.c — CryptUnprotectData wrapper
 *
 * Decrypts DPAPI-protected data blobs used by browsers and the OS.
 * Windows-only implementation; returns error on other platforms.
 */

#include "dpapi_unprotect.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

/* MinGW BCrypt/Crypt compatibility — explicit types and declarations */
#ifndef CRYPTPROTECT_UI_FORBIDDEN
#define CRYPTPROTECT_UI_FORBIDDEN 0x01
#endif

/* DATA_BLOB may not be defined with WIN32_LEAN_AND_MEAN */
#ifndef _WINCRYPT_H
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
} DATA_BLOB, *PDATA_BLOB, CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,
  CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB, CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,
  CERT_NAME_BLOB, *PCERT_NAME_BLOB, CERT_RDN_VALUE_BLOB, *PCERT_RDN_VALUE_BLOB,
  CERT_BLOB, *PCERT_BLOB, CRL_BLOB, *PCRL_BLOB, DATA_BLOB, *PDATA_BLOB,
  DATA_BLOB, *PPDATA_BLOB;
#endif

/* CryptUnprotectData is declared in dpapi.h */

/* Maximum input size: 1 MB */
#define DPAPI_MAX_INPUT (1024 * 1024)

/* DPAPI_BLOB layout for CryptUnprotectData output */
typedef struct {
    DWORD cbData;
    BYTE *pbData;
} DPAPI_BLOB;

int dpapi_decrypt(const unsigned char *input, size_t input_len,
                  unsigned char **output, size_t *out_len) {
    return dpapi_decrypt_ex(input, input_len, NULL, 0, output, out_len);
}

int dpapi_decrypt_ex(const unsigned char *input, size_t input_len,
                     const unsigned char *entropy, size_t entropy_len,
                     unsigned char **output, size_t *out_len) {
    if (input_len == 0 || input_len > DPAPI_MAX_INPUT)
        return -1;
    if (!output || !out_len)
        return -1;

    *output = NULL;
    *out_len = 0;

    DATA_BLOB blob_in;
    blob_in.cbData = (DWORD)input_len;
    blob_in.pbData = (BYTE *)input;

    DATA_BLOB blob_entropy;
    DATA_BLOB *p_entropy = NULL;
    if (entropy && entropy_len > 0) {
        blob_entropy.cbData = (DWORD)entropy_len;
        blob_entropy.pbData = (BYTE *)entropy;
        p_entropy = &blob_entropy;
    }

    DATA_BLOB blob_out;
    memset(&blob_out, 0, sizeof(blob_out));

    BOOL result = CryptUnprotectData(
        &blob_in,
        NULL,           /* ppszDataDescr */
        p_entropy,      /* pOptionalEntropy */
        NULL,           /* pvReserved */
        NULL,           /* pPromptStruct */
        0,              /* dwFlags — no UI */
        &blob_out
    );

    if (!result || blob_out.cbData == 0) {
        if (blob_out.pbData)
            LocalFree(blob_out.pbData);
        return -1;
    }

    /* Copy result to caller-allocated buffer */
    *output = (unsigned char *)malloc(blob_out.cbData);
    if (!*output) {
        LocalFree(blob_out.pbData);
        return -1;
    }

    memcpy(*output, blob_out.pbData, blob_out.cbData);
    *out_len = (size_t)blob_out.cbData;

    LocalFree(blob_out.pbData);
    return 0;
}

int dpapi_decrypt_chrome_key(const unsigned char *input, size_t input_len,
                             unsigned char **output, size_t *out_len) {
    if (input_len < 2)
        return -1;

    /* Chrome prefix: byte 0 = version (0x01), rest = DPAPI blob */
    if (input[0] != 0x01)
        return -1;

    return dpapi_decrypt(input + 1, input_len - 1, output, out_len);
}

#else

/* ═══════════════════════════════════════════════════════════════
 *  Linux stubs — DPAPI is Windows-only
 * ═══════════════════════════════════════════════════════════════ */

int dpapi_decrypt(const unsigned char *input, size_t input_len,
                  unsigned char **output, size_t *out_len) {
    (void)input; (void)input_len; (void)output; (void)out_len;
    return -1;
}

int dpapi_decrypt_ex(const unsigned char *input, size_t input_len,
                     const unsigned char *entropy, size_t entropy_len,
                     unsigned char **output, size_t *out_len) {
    (void)input; (void)input_len; (void)entropy; (void)entropy_len;
    (void)output; (void)out_len;
    return -1;
}

int dpapi_decrypt_chrome_key(const unsigned char *input, size_t input_len,
                             unsigned char **output, size_t *out_len) {
    (void)input; (void)input_len; (void)output; (void)out_len;
    return -1;
}

#endif
