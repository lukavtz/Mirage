#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <stddef.h>

// Read the current clipboard text (UTF-8) into buf.
// Returns 0 on success, -1 on failure.
int clipboard_get_text(char *buf, size_t buf_len);

// Return the current clipboard sequence number.
unsigned int clipboard_get_sequence(void);

#endif
