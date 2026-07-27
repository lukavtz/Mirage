#ifndef DPAPI_UNPROTECT_H
#define DPAPI_UNPROTECT_H

#include <stddef.h>
#include <stdint.h>

/*
 * DPAPI — CryptUnprotectData wrapper
 *
 * Decrypts DPAPI-protected data blobs (e.g., Chrome master keys).
 * Windows-only; returns error on other platforms.
 */

/*
 * Decrypt a DPAPI-protected blob.
 * Input is the raw encrypted data (without any prefix).
 * Output is dynamically allocated; caller must free() it.
 * out_len receives the decrypted size.
 * Returns 0 on success, -1 on failure.
 */
int dpapi_decrypt(const unsigned char *input, size_t input_len,
                  unsigned char **output, size_t *output_len);

/*
 * Decrypt with optional entropy (additional protection data).
 * entropy can be NULL for standard DPAPI calls.
 */
int dpapi_decrypt_ex(const unsigned char *input, size_t input_len,
                     const unsigned char *entropy, size_t entropy_len,
                     unsigned char **output, size_t *output_len);

/*
 * Decrypt a Chrome-style DPAPI key (version prefix stripped).
 * input[0] is the version byte (0x01), followed by the encrypted blob.
 * Returns decrypted key in *output (caller must free).
 */
int dpapi_decrypt_chrome_key(const unsigned char *input, size_t input_len,
                             unsigned char **output, size_t *output_len);

#endif
