/*
 * hash.c — Hash functions for Mirage-C
 *
 * Exact translation of Zig src/types/hash.zig
 * Seed: 0x61472f96, multiply: 0x1B873593, add: 0x85EBCA6B
 */

#include "hash.h"
#include "config.h"
#include <string.h>

/* ── Internal: Rotl32 ─────────────────────────────────────── */
static inline uint32_t rotl32(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

/* ── hashString: case-insensitive hash (module names) ──────── */
uint32_t mirage_hash_string(const uint8_t* str, size_t len, uint32_t iterations)
{
    uint32_t hash = MIRAGE_SEED;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = str[i];

        /* Lowercase: A-Z → a-z */
        if (c >= 'A' && c <= 'Z')
            c += 32;

        for (uint32_t j = 0; j < iterations; j++) {
            hash = rotl32(hash, 5);
            hash ^= c;
            hash = hash * 0x1B873593u + 0x85EBCA6Bu;
        }
    }

    return hash;
}

/* ── hashStringExact: exact-case hash (function names) ─────── */
uint32_t mirage_hash_string_exact(const uint8_t* str, size_t len, uint32_t iterations)
{
    uint32_t hash = MIRAGE_SEED;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = str[i];

        for (uint32_t j = 0; j < iterations; j++) {
            hash = rotl32(hash, 5);
            hash ^= c;
            hash = hash * 0x1B873593u + 0x85EBCA6Bu;
        }
    }

    return hash;
}

/* ── XOR encrypt/decrypt with repeating 16-byte key ────────── */
void mirage_xor_encrypt(const uint8_t* in, uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ MIRAGE_STRING_KEY_ENC[i % 16];
    }
}

void mirage_xor_decrypt(const uint8_t* in, uint8_t* out, size_t len)
{
    /* XOR is symmetric: decrypt == encrypt */
    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ MIRAGE_STRING_KEY_ENC[i % 16];
    }
}

/* ── encryptedHashModule: XOR-encrypt then hash (28 iters) ─── */
uint32_t mirage_encrypted_hash_module(const char* str)
{
    size_t len = strlen(str);
    uint8_t buf[256];

    /* XOR-encrypt input */
    mirage_xor_encrypt((const uint8_t*)str, buf, len);

    /* Hash with case folding, 28 iterations (module hash) */
    return mirage_hash_string(buf, len, 28);
}

/* ── encryptedHashFunc: XOR-encrypt then hash (27 iters) ───── */
uint32_t mirage_encrypted_hash_func(const char* str)
{
    size_t len = strlen(str);
    uint8_t buf[256];

    /* XOR-encrypt input */
    mirage_xor_encrypt((const uint8_t*)str, buf, len);

    /* Hash without case folding, 27 iterations (function hash) */
    return mirage_hash_string_exact(buf, len, 27);
}
