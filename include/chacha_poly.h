#ifndef CHACHA_POLY_H
#define CHACHA_POLY_H

#include <stddef.h>
#include <stdint.h>

/*
 * ChaCha20-Poly1305 AEAD — RFC 8439
 *
 * Encrypt: plaintext → ciphertext || tag (16 bytes)
 * Decrypt: ciphertext || tag → plaintext, returns 0 on auth success
 *
 * All functions return 0 on success, -1 on error.
 */

#define CHACHA_POLY_KEY_LEN   32
#define CHACHA_POLY_NONCE_LEN 12
#define CHACHA_POLY_TAG_LEN   16

/*
 * Encrypt plaintext with associated data.
 * out must hold at least pt_len + CHACHA_POLY_TAG_LEN bytes.
 * out_len is set to pt_len + 16.
 */
int chacha_poly_encrypt(const unsigned char *pt, size_t pt_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len);

/*
 * Decrypt ciphertext || tag with associated data.
 * out must hold at least ct_len - 16 bytes.
 * out_len is set to ct_len - 16 on success.
 * Returns -1 on authentication failure.
 */
int chacha_poly_decrypt(const unsigned char *ct, size_t ct_len,
                        const unsigned char key[CHACHA_POLY_KEY_LEN],
                        const unsigned char nonce[CHACHA_POLY_NONCE_LEN],
                        const unsigned char *ad, size_t ad_len,
                        unsigned char *out, size_t *out_len);

#endif
