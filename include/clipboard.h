#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <stddef.h>

// Get text from clipboard as UTF-8 into buf. Returns 0 on success, -1 on failure.
int clipboard_get_text(char *buf, size_t buf_len);

// Get current clipboard sequence number for change detection.
unsigned int clipboard_get_sequence(void);

#endif
