#ifndef CHROME_CRYPTO_H
#define CHROME_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Extract the base64-encoded encrypted_key from a Local State JSON blob.
 * Returns decoded bytes in `out`, sets `out_len`. Returns 0 on success.
 */
int chrome_extract_encrypted_key(const char *json, size_t json_len,
                                 unsigned char *out, size_t out_max,
                                 size_t *out_len);

/*
 * Decrypt the DPAPI-encrypted key blob (v1 prefix → CryptUnprotectData).
 * `encrypted_key` is the raw decoded bytes from Local State (byte 0 = version).
 * Returns decrypted AES key in `out`, sets `out_len`. Returns 0 on success.
 */
int chrome_decrypt_dpapi_key(const unsigned char *encrypted_key, size_t len,
                             unsigned char *out, size_t out_max,
                             size_t *out_len);

/*
 * Derive the v10/v11 master key from empty password using PBKDF2-SHA1.
 * Salt = "saltysalt", iterations = 1.
 * Returns 32-byte key in `out`. Returns 0 on success.
 */
int chrome_derive_key(unsigned char *out32);

/*
 * Decrypt a v10/v11 Chrome encrypted value using AES-256-GCM.
 * Format: "v10" or "v11" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes).
 * Returns plaintext in `out`, sets `out_len`. Returns 0 on success.
 */
int chrome_decrypt_password(const unsigned char *encrypted, size_t len,
                            const unsigned char *key32,
                            unsigned char *out, size_t out_max,
                            size_t *out_len);

/*
 * Base64 decode. Returns decoded length, -1 on error.
 */
int chrome_base64_decode(const char *input, size_t input_len,
                         unsigned char *out, size_t out_max);

#endif
