#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <stddef.h>

/* Capture desktop screenshot and save to file (BMP format) */
int screenshot_capture(const char *output_path);

/* Capture desktop screenshot into heap-allocated buffer (caller must free *buf) */
int screenshot_capture_to_buffer(unsigned char **buf, size_t *len);

#endif /* SCREENSHOT_H */
