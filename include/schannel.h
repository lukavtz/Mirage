#ifndef ZIALFI_SCHANNEL_H
#define ZIALFI_SCHANNEL_H

#include "ws2.h"
#include <stdint.h>
#include <stddef.h>

typedef enum {
    TLS_OK = 0,
    TLS_ERR_CRED_FAILED,
    TLS_ERR_HANDSHAKE_FAILED,
    TLS_ERR_ENCRYPT_FAILED,
    TLS_ERR_DECRYPT_FAILED,
    TLS_ERR_INCOMPLETE,
    TLS_ERR_STREAM_SIZES,
    TLS_ERR_FREE_CTX,
    TLS_ERR_DELETE_CTX,
} tls_result_t;

typedef struct {
    HANDLE   sock;
    uint32_t cred_lower;
    uint32_t cred_upper;
    uint32_t ctx_lower;
    uint32_t ctx_upper;
    uint32_t header_size;
    uint32_t trailer_size;
    uint32_t max_message;
} tls_context_t;

/*
 * Perform TLS handshake over an already-connected TCP socket.
 * `hostname` is used for SNI. Returns TLS_OK on success.
 */
tls_result_t tls_connect(tls_context_t *ctx, HANDLE sock, const char *hostname);

/*
 * Send `data` (length `len`) through the TLS layer.
 * Handles chunking for records that exceed max_message.
 * Returns TLS_OK on success; *out_sent is the plaintext bytes written.
 */
tls_result_t tls_send(tls_context_t *ctx, const uint8_t *data, size_t len, size_t *out_sent);

/*
 * Receive and decrypt one TLS record into `buf` (up to `buf_len` bytes).
 * Returns TLS_OK on success; *out_read is the decrypted byte count.
 */
tls_result_t tls_recv(tls_context_t *ctx, uint8_t *buf, size_t buf_len, size_t *out_read);

/*
 * Tear down TLS context and free credentials.
 */
void tls_disconnect(tls_context_t *ctx);

#endif /* ZIALFI_SCHANNEL_H */
