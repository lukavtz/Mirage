#ifndef ZIALFI_WS2_H
#define ZIALFI_WS2_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
typedef void *HANDLE;
#else
typedef int HANDLE;
#endif

typedef enum {
    WS2_OK = 0,
    WS2_ERR_INIT_FAILED,
    WS2_ERR_SOCKET_FAILED,
    WS2_ERR_CONNECT_FAILED,
    WS2_ERR_RESOLVE_FAILED,
    WS2_ERR_SEND_FAILED,
    WS2_ERR_RECV_FAILED,
    WS2_ERR_BIND_FAILED,
    WS2_ERR_LISTEN_FAILED,
    WS2_ERR_ACCEPT_FAILED,
    WS2_ERR_SETOPT_FAILED,
    WS2_ERR_MODULE_NOT_FOUND,
    WS2_ERR_FUNC_NOT_FOUND,
} ws2_result_t;

typedef struct {
    HANDLE handle;
} ws2_socket_t;

ws2_result_t ws2_init(void);
void         ws2_cleanup(void);

ws2_result_t ws2_connect(ws2_socket_t *out, const char *host, uint16_t port);
ws2_result_t ws2_send(HANDLE sock, const uint8_t *data, size_t len, size_t *out_sent);
ws2_result_t ws2_recv(HANDLE sock, uint8_t *buf, size_t buf_len, size_t *out_read);
void         ws2_close(HANDLE sock);

ws2_result_t ws2_create_raw(HANDLE *out);
ws2_result_t ws2_bind(HANDLE sock, const char *host, uint16_t port);
ws2_result_t ws2_listen(HANDLE sock, int backlog);
ws2_result_t ws2_accept(HANDLE listener, HANDLE *out_client);
ws2_result_t ws2_set_reuseaddr(HANDLE sock);
uint16_t     ws2_get_port(HANDLE sock);

uint32_t ws2_parse_ipv4(const char *host);

#endif /* ZIALFI_WS2_H */
