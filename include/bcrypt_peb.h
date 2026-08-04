/*
 * bcrypt_peb.h — PEB-resolved BCrypt API function pointers
 *
 * Shared singleton for all BCrypt calls. Resolves bcrypt.dll via
 * PEB-walk + hash-based export table parsing at first use.
 */
#ifndef MIRAGE_BCRYPT_PEB_H
#define MIRAGE_BCRYPT_PEB_H

#include <windows.h>
#include <bcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BCrypt function pointer types */
typedef NTSTATUS (WINAPI *pBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *pBCryptSetProperty)(BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *,
                                                        PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDeriveKeyPBKDF2)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG,
                                                    PUCHAR, ULONG, ULONGLONG,
                                                    PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID,
                                            PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pBCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *,
                                               PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDestroyHash)(BCRYPT_HASH_HANDLE);
typedef NTSTATUS (WINAPI *pBCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);

typedef struct {
    pBCryptOpenAlgorithmProvider  pOpen;
    pBCryptCloseAlgorithmProvider pClose;
    pBCryptSetProperty            pSetProp;
    pBCryptGenerateSymmetricKey   pGenKey;
    pBCryptDeriveKeyPBKDF2        pDerive;
    pBCryptDecrypt                pDecrypt;
    pBCryptDestroyKey             pDestroyKey;
    pBCryptCreateHash             pCreateHash;
    pBCryptHashData               pHashData;
    pBCryptFinishHash             pFinishHash;
    pBCryptDestroyHash            pDestroyHash;
    pBCryptGenRandom              pGenRandom;
    int ready;
} bcrypt_api_t;

/*
 * Returns pointer to the shared BCrypt API singleton.
 * Resolves all function pointers via PEB-walk on first call.
 * Returns NULL if bcrypt.dll is not loaded or resolution fails.
 */
const bcrypt_api_t *mirage_bcrypt_api(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_BCRYPT_PEB_H */
