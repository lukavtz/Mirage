#include "ws2.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#endif

#include <stdlib.h>
#include <string.h>

/* ── platform abstractions ─────────────────────────────────────── */

#ifdef _WIN32
typedef WSADATA ws2_wsa_data_t;
#define WS2_INVALID_SOCKET  ((HANDLE)(intptr_t)(~0))
#define WS2_SOCK_ERROR(s)   ((s) == INVALID_SOCKET)
#define ws2_closesocket(s)  closesocket((SOCKET)(s))
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
    ws2_wsa_data_t wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return WS2_ERR_INIT_FAILED;
#endif
    g_ws2_initialized = 1;
    return WS2_OK;
}

void ws2_cleanup(void) {
    if (!g_ws2_initialized) return;
#ifdef _WIN32
    WSACleanup();
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
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                          NULL, 0, WSA_FLAG_OVERLAPPED);
    if (WS2_SOCK_ERROR(s)) return WS2_ERR_SOCKET_FAILED;
#else
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return WS2_ERR_SOCKET_FAILED;
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

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

        if (getaddrinfo(host_buf, NULL, &hints, &res) != 0 || !res) {
            ws2_closesocket(s);
            return WS2_ERR_RESOLVE_FAILED;
        }
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ws2_closesocket(s);
        return WS2_ERR_CONNECT_FAILED;
    }

    out->initialized = 1;
#ifdef _WIN32
    /* store as HANDLE */
    (void)0; /* s already SOCKET, cast to HANDLE at return */
#endif
    (void)out; /* suppress unused in POSIX path */
#ifdef _WIN32
    /* pack SOCKET into HANDLE-sized slot */
    *((SOCKET *)out) = s;
#else
    *(int *)out = s;
#endif
    return WS2_OK;
}

ws2_result_t ws2_send(HANDLE sock, const uint8_t *data, size_t len, size_t *out_sent) {
    if (!data || len == 0) { if (out_sent) *out_sent = 0; return WS2_OK; }
#ifdef _WIN32
    int rc = send((SOCKET)sock, (const char *)data, (int)len, 0);
#else
    int rc = send((int)sock, data, len, 0);
#endif
    if (rc < 0) return WS2_ERR_SEND_FAILED;
    if (out_sent) *out_sent = (size_t)rc;
    return WS2_OK;
}

ws2_result_t ws2_recv(HANDLE sock, uint8_t *buf, size_t buf_len, size_t *out_read) {
    if (!buf || buf_len == 0) { if (out_read) *out_read = 0; return WS2_OK; }
#ifdef _WIN32
    int rc = recv((SOCKET)sock, (char *)buf, (int)buf_len, 0);
#else
    int rc = recv((int)sock, buf, buf_len, 0);
#endif
    if (rc < 0) return WS2_ERR_RECV_FAILED;
    if (out_read) *out_read = (size_t)rc;
    return WS2_OK;
}

void ws2_close(HANDLE sock) {
    if (sock == NULL) return;
#ifdef _WIN32
    closesocket((SOCKET)sock);
#else
    close((int)(intptr_t)sock);
#endif
}

/* ── raw socket helpers ────────────────────────────────────────── */

ws2_result_t ws2_create_raw(HANDLE *out) {
    ws2_result_t r = ws2_init();
    if (r != WS2_OK) return r;
#ifdef _WIN32
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
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
    addr.sin_port   = htons(port);

    if (host && *host) {
        uint32_t ip = ws2_parse_ipv4(host);
        if (ip != 0) {
            addr.sin_addr.s_addr = ip;
        } else {
            struct addrinfo hints, *res;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
                return WS2_ERR_RESOLVE_FAILED;
            addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

#ifdef _WIN32
    if (bind((SOCKET)sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
#else
    if (bind((int)(intptr_t)sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
#endif
        return WS2_ERR_BIND_FAILED;
    return WS2_OK;
}

ws2_result_t ws2_listen(HANDLE sock, int backlog) {
#ifdef _WIN32
    if (listen((SOCKET)sock, backlog) != 0)
#else
    if (listen((int)(intptr_t)sock, backlog) != 0)
#endif
        return WS2_ERR_LISTEN_FAILED;
    return WS2_OK;
}

ws2_result_t ws2_accept(HANDLE listener, HANDLE *out_client) {
#ifdef _WIN32
    SOCKET c = accept((SOCKET)listener, NULL, NULL);
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
    if (setsockopt((SOCKET)sock, SOL_SOCKET, SO_REUSEADDR,
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
    int len = sizeof(sin);
    if (getsockname((SOCKET)sock, (struct sockaddr *)&sin, &len) != 0)
#else
    socklen_t len = sizeof(sin);
    if (getsockname((int)(intptr_t)sock, (struct sockaddr *)&sin, &len) != 0)
#endif
        return 0;
    return ntohs(sin.sin_port);
}
