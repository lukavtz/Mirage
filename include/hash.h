/*
 * hash.h — Hash functions for Mirage-C
 *
 * Rotl-XOR-Mul hash matching Zig config.SEED (polymorphic)
 * Module hashes use 28 iterations, function hashes use 27.
 * All hashes XOR input bytes with STRING_KEY_ENC before hashing.
 */

#ifndef MIRAGE_HASH_H
#define MIRAGE_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hashString — Rotl-XOR-Mul hash with case folding.
 *
 * Algorithm (matching Zig hashString):
 *   for each byte c in str (lowercased):
 *     for 0..iterations:
 *       hash = rotl32(hash, 5) ^ c
 *       hash = hash * 0x1B873593 + 0x85EBCA6B
 *
 * Used for module names (28 iterations).
 */
uint32_t mirage_hash_string(const uint8_t* str, size_t len, uint32_t iterations);

/*
 * hashStringExact — Same as hashString but without case folding.
 *
 * Used for function names (27 iterations).
 */
uint32_t mirage_hash_string_exact(const uint8_t* str, size_t len, uint32_t iterations);

/*
 * encryptedHashModule — XOR-encrypt str with STRING_KEY_ENC, then hash.
 * 28 iterations (module name hash).
 */
uint32_t mirage_encrypted_hash_module(const char* str);

/*
 * encryptedHashFunc — XOR-encrypt str with STRING_KEY_ENC, then hash.
 * 27 iterations (function name hash).
 */
uint32_t mirage_encrypted_hash_func(const char* str);

/*
 * xorEncrypt — XOR-encrypt a buffer with STRING_KEY_ENC (repeating key).
 * out must be at least len bytes.
 */
void mirage_xor_encrypt(const uint8_t* in, uint8_t* out, size_t len);

/*
 * xorDecrypt — XOR-decrypt a buffer with STRING_KEY_ENC (repeating key).
 * out must be at least len bytes.
 */
void mirage_xor_decrypt(const uint8_t* in, uint8_t* out, size_t len);

/*
 * readU32Le — Read a little-endian uint32 from a byte pointer.
 */
static inline uint32_t mirage_read_u32_le(const uint8_t* ptr)
{
    return (uint32_t)ptr[0]
         | ((uint32_t)ptr[1] << 8)
         | ((uint32_t)ptr[2] << 16)
         | ((uint32_t)ptr[3] << 24);
}

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_HASH_H */
