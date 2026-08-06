#include "ws2.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ws2_peb.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <string.h>

/* ── platform abstractions ─────────────────────────────────────── */

#ifdef _WIN32
typedef WSADATA ws2_wsa_data_t;
#define WS2_INVALID_SOCKET  ((HANDLE)(intptr_t)(~0))
#define WS2_SOCK_ERROR(s)   ((s) == INVALID_SOCKET)
#define ws2_closesocket(s)  mirage_ws2_api()->pclosesocket((SOCKET)(s))
#else
typedef struct { int dummy; } ws2_wsa_data_t;
#define WS2_INVALID_SOCKET  (-1)
#define WS2_SOCK_ERROR(s)   ((s) < 0)
#define ws2_closesocket(s)  close((int)(s))
#endif

/* ── global state ──────────────────────────────────────────────── */

static int g_ws2_initialized = 0;

ws2_result_t ws2_init(void) {
    if (g_ws2_initialized) return WS2_OK;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (!api) return WS2_ERR_MODULE_NOT_FOUND;
    ws2_wsa_data_t wsa;
    if (api->pStartup(MAKEWORD(2, 2), &wsa) != 0)
        return WS2_ERR_INIT_FAILED;
#endif
    g_ws2_initialized = 1;
    return WS2_OK;
}

void ws2_cleanup(void) {
    if (!g_ws2_initialized) return;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (api) api->pCleanup();
#endif
    g_ws2_initialized = 0;
}

/* ── IPv4 dotted-decimal parser ────────────────────────────────── */

uint32_t ws2_parse_ipv4(const char *host) {
    uint32_t result = 0;
    uint32_t octet = 0;
    int      octets = 0;

    for (const char *p = host; *p; ++p) {
        char c = *p;
        if (c == '.') {
            if (octets >= 3 || octet > 255) return 0;
            result = (result << 8) | octet;
            octet = 0;
            octets++;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (uint32_t)(c - '0');
            if (octet > 255) return 0;
        } else {
            return 0;
        }
    }
    if (octets != 3 || octet > 255) return 0;
    result = (result << 8) | octet;
    /* network byte order: byte-swap on little-endian */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    result = __builtin_bswap32(result);
#endif
    return result;
}

/* ── socket lifecycle ──────────────────────────────────────────── */

ws2_result_t ws2_connect(ws2_socket_t *out, const char *host, uint16_t port) {
    ws2_result_t r = ws2_init();
    if (r != WS2_OK) return r;

#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (!api) return WS2_ERR_MODULE_NOT_FOUND;

    SOCKET s = api->pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                 NULL, 0, WSA_FLAG_OVERLAPPED);
    if (WS2_SOCK_ERROR(s)) return WS2_ERR_SOCKET_FAILED;
#else
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return WS2_ERR_SOCKET_FAILED;
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
#ifdef _WIN32
    addr.sin_port   = api->phtons(port);
#else
    addr.sin_port   = htons(port);
#endif

    /* try direct parse first, then getaddrinfo fallback */
    uint32_t ip = ws2_parse_ipv4(host);
    if (ip != 0) {
        addr.sin_addr.s_addr = ip;
    } else {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        char host_buf[256];
        size_t hlen = strlen(host);
        if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
        memcpy(host_buf, host, hlen);
        host_buf[hlen] = '\0';

#ifdef _WIN32
        if (api->pgetaddrinfo(host_buf, NULL, &hints, &res) != 0 || !res) {
#else
        if (getaddrinfo(host_buf, NULL, &hints, &res) != 0 || !res) {
#endif
            ws2_closesocket(s);
            return WS2_ERR_RESOLVE_FAILED;
        }
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
#ifdef _WIN32
        api->pfreeaddrinfo(res);
#else
        freeaddrinfo(res);
#endif
    }

    /* Set socket timeouts — 15 seconds */
#ifdef _WIN32
    {
        DWORD timeout_ms = 15000;
        api->psetsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
        api->psetsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    }
#else
    {
        struct timeval tv;
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif

#ifdef _WIN32
    if (api->pconnect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#else
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#endif
        ws2_closesocket(s);
        return WS2_ERR_CONNECT_FAILED;
    }

#ifdef _WIN32
    out->handle = (HANDLE)(ULONG_PTR)s;
#else
    out->handle = (HANDLE)(intptr_t)s;
#endif
    return WS2_OK;
}

ws2_result_t ws2_send(HANDLE sock, const uint8_t *data, size_t len, size_t *out_sent) {
    if (!data || len == 0) { if (out_sent) *out_sent = 0; return WS2_OK; }
    size_t total = 0;
    while (total < len) {
        size_t chunk = len - total;
#ifdef _WIN32
        if (chunk > 0x7FFFFFFF) chunk = 0x7FFFFFFF;
        const ws2_api_t *api = mirage_ws2_api();
        if (!api) { if (out_sent) *out_sent = total; return WS2_ERR_MODULE_NOT_FOUND; }
        int rc = api->psend((SOCKET)sock, (const char *)(data + total), (int)chunk, 0);
#else
        if (chunk > INT_MAX) chunk = INT_MAX;
        int rc = send((int)sock, data + total, chunk, 0);
#endif
        if (rc <= 0) { if (out_sent) *out_sent = total; return WS2_ERR_SEND_FAILED; }
        total += (size_t)rc;
    }
    if (out_sent) *out_sent = total;
    return WS2_OK;
}

ws2_result_t ws2_recv(HANDLE sock, uint8_t *buf, size_t buf_len, size_t *out_read) {
    if (!buf || buf_len == 0) { if (out_read) *out_read = 0; return WS2_OK; }
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    int rc = api->precv((SOCKET)sock, (char *)buf, (int)buf_len, 0);
#else
    int rc = recv((int)sock, buf, buf_len, 0);
    if (rc < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (out_read) *out_read = 0;
            return WS2_OK;
        }
        return WS2_ERR_RECV_FAILED;
    }
#endif
    if (rc < 0) return WS2_ERR_RECV_FAILED;
    if (out_read) *out_read = (size_t)rc;
    return WS2_OK;
}

void ws2_close(HANDLE sock) {
    if (sock == NULL) return;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (api) api->pclosesocket((SOCKET)sock);
#else
    close((int)(intptr_t)sock);
#endif
}

/* ── raw socket helpers ────────────────────────────────────────── */

ws2_result_t ws2_create_raw(HANDLE *out) {
    ws2_result_t r = ws2_init();
    if (r != WS2_OK) return r;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (!api) return WS2_ERR_MODULE_NOT_FOUND;
    /* L6: WS2_SOCK_ERROR checks INVALID_SOCKET (not NULL) — correct for WSASocketW */
    SOCKET s = api->pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                 NULL, 0, WSA_FLAG_OVERLAPPED);
    if (WS2_SOCK_ERROR(s)) return WS2_ERR_SOCKET_FAILED;
    *out = (HANDLE)s;
#else
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return WS2_ERR_SOCKET_FAILED;
    *out = (HANDLE)(intptr_t)s;
#endif
    return WS2_OK;
}

ws2_result_t ws2_bind(HANDLE sock, const char *host, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (!api) return WS2_ERR_MODULE_NOT_FOUND;
    addr.sin_port   = api->phtons(port);
#else
    addr.sin_port   = htons(port);
#endif

    if (host && *host) {
        uint32_t ip = ws2_parse_ipv4(host);
        if (ip != 0) {
            addr.sin_addr.s_addr = ip;
        } else {
            struct addrinfo hints, *res;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
#ifdef _WIN32
            if (api->pgetaddrinfo(host, NULL, &hints, &res) != 0 || !res)
#else
            if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
#endif
                return WS2_ERR_RESOLVE_FAILED;
            addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
#ifdef _WIN32
            api->pfreeaddrinfo(res);
#else
            freeaddrinfo(res);
#endif
        }
    } else {
#ifdef _WIN32
        addr.sin_addr.s_addr = api->phtonl(INADDR_ANY);
#else
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
    }

#ifdef _WIN32
    if (api->pbind((SOCKET)sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
#else
    if (bind((int)(intptr_t)sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
#endif
        return WS2_ERR_BIND_FAILED;
    return WS2_OK;
}

ws2_result_t ws2_listen(HANDLE sock, int backlog) {
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (api->plisten((SOCKET)sock, backlog) != 0)
#else
    if (listen((int)(intptr_t)sock, backlog) != 0)
#endif
        return WS2_ERR_LISTEN_FAILED;
    return WS2_OK;
}

ws2_result_t ws2_accept(HANDLE listener, HANDLE *out_client) {
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    SOCKET c = api->paccept((SOCKET)listener, NULL, NULL);
    if (WS2_SOCK_ERROR(c)) return WS2_ERR_ACCEPT_FAILED;
    *out_client = (HANDLE)c;
#else
    int c = accept((int)(intptr_t)listener, NULL, NULL);
    if (c < 0) return WS2_ERR_ACCEPT_FAILED;
    *out_client = (HANDLE)(intptr_t)c;
#endif
    return WS2_OK;
}

ws2_result_t ws2_set_reuseaddr(HANDLE sock) {
    int optval = 1;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    if (api->psetsockopt((SOCKET)sock, SOL_SOCKET, SO_REUSEADDR,
                          (const char *)&optval, sizeof(optval)) != 0)
#else
    if (setsockopt((int)(intptr_t)sock, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)) != 0)
#endif
        return WS2_ERR_SETOPT_FAILED;
    return WS2_OK;
}

uint16_t ws2_get_port(HANDLE sock) {
    struct sockaddr_in sin;
#ifdef _WIN32
    const ws2_api_t *api = mirage_ws2_api();
    int len = sizeof(sin);
    if (api->pgetsockname((SOCKET)sock, (struct sockaddr *)&sin, &len) != 0)
        return 0;
    return api->pntohs(sin.sin_port);
#else
    socklen_t len = sizeof(sin);
    if (getsockname((int)(intptr_t)sock, (struct sockaddr *)&sin, &len) != 0)
        return 0;
    return ntohs(sin.sin_port);
#endif
}
