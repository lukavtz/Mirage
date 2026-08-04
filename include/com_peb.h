/*
 * com_peb.h — PEB-resolved COM API function pointers
 *
 * Shared singleton for CoInitializeEx, CoCreateInstance, CoUninitialize.
 * Resolves ole32.dll via PEB-walk + hash-based export table parsing.
 */
#ifndef MIRAGE_COM_PEB_H
#define MIRAGE_COM_PEB_H

#include <windows.h>
#include <objbase.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HRESULT (WINAPI *pCoInitializeEx)(LPVOID, DWORD);
typedef HRESULT (WINAPI *pCoCreateInstance)(REFCLSID, LPVOID, DWORD, REFIID, LPVOID *);
typedef HRESULT (WINAPI *pCoSetProxyBlanket)(IUnknown *, DWORD, DWORD, OLECHAR *,
                                               DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
typedef void    (WINAPI *pCoUninitialize)(void);

typedef struct {
    pCoInitializeEx    pInit;
    pCoCreateInstance  pCreate;
    pCoSetProxyBlanket pBlanket;
    pCoUninitialize    pUninit;
    int ready;
} com_api_t;

const com_api_t *mirage_com_api(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_COM_PEB_H */
