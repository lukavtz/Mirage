#ifndef ARCHIVE_CRYPT_H
#define ARCHIVE_CRYPT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Archive encryption — wraps ChaCha20-Poly1305 with PBKDF2 key derivation.
 *
 * Format: [nonce (12)] [salt (16)] [ciphertext] [tag (16)]
 *
 * Key is derived from a seed constant via PBKDF2-SHA256.
 * Each encryption generates a random nonce and salt for semantic security.
 */

#define ARCHIVE_SALT_LEN 16
#define ARCHIVE_HEADER_LEN (12 + ARCHIVE_SALT_LEN)  /* nonce + salt */

/*
 * Derive a 32-byte key from password and salt using PBKDF2-SHA256.
 * iterations = 210000 (matching the Zig reference).
 * Returns 0 on success.
 */
int archive_derive_key(const unsigned char *password, size_t password_len,
                       const unsigned char *salt, size_t salt_len,
                       unsigned char out_key[32]);

/*
 * Encrypt plaintext into output buffer.
 * out must hold at least ARCHIVE_HEADER_LEN + pt_len + 16 bytes.
 * out_len is set to the total output size.
 * Returns 0 on success.
 */
int archive_encrypt(const unsigned char *pt, size_t pt_len,
                    const unsigned char *key, size_t key_len,
                    unsigned char *out, size_t *out_len);

/*
 * Decrypt ciphertext into output buffer.
 * Returns 0 on success, -1 on authentication failure.
 */
int archive_decrypt(const unsigned char *ct, size_t ct_len,
                    const unsigned char *key, size_t key_len,
                    unsigned char *out, size_t *out_len);

#endif
