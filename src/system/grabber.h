#ifndef GRABBER_H
#define GRABBER_H

#include <stddef.h>

// Collect files from Desktop/Documents/Downloads into output_dir
// Returns number of files collected, -1 on error
int grabber_collect(const char *output_dir, size_t max_files);

#endif
