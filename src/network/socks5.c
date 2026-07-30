#include "socks5.h"
#include "ws2.h"
#include "config.h"

#ifdef ENABLE_SOCKS5

#ifdef _WIN32
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

#define SOCKS5_VER             0x05
#define SOCKS5_CMD_CONNECT     0x01
#define SOCKS5_ATYP_IPV4       0x01
#define SOCKS5_ATYP_DOMAIN     0x03
#define SOCKS5_REP_SUCCESS     0x00
#define SOCKS5_METHOD_NO_AUTH  0x00

static int socks5_send_all(SOCKET sock, const void *data, size_t len) {
    const char *ptr = (const char *)data;
    while (len > 0) {
#ifdef _WIN32
        int n = send(sock, ptr, (int)len, 0);
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
        int n = recv(sock, ptr, (int)len, 0);
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
    addr.sin_port = htons(port);

    uint32_t ip = inet_addr(host);
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

        if (getaddrinfo(buf, NULL, &hints, &res) != 0 || !res) return -1;
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    } else {
        addr.sin_addr.s_addr = ip;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
    return 0;
}

int socks5_connect(const char *proxy_host, uint16_t proxy_port,
                   const char *target_host, uint16_t target_port,
                   SOCKET *out_sock) {
    if (!proxy_host || !target_host || !out_sock) return -1;
    if (ws2_init() != WS2_OK) return -1;

#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return -1;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
#endif

    if (socks5_connect_host(sock, proxy_host, proxy_port) != 0) {
        closesocket(sock);
        return -1;
    }

    unsigned char method_req[] = {SOCKS5_VER, 0x01, SOCKS5_METHOD_NO_AUTH};
    if (socks5_send_all(sock, method_req, sizeof(method_req)) != 0) {
        closesocket(sock);
        return -1;
    }

    unsigned char method_resp[2];
    if (socks5_recv_all(sock, method_resp, 2) != 0) {
        closesocket(sock);
        return -1;
    }

    if (method_resp[0] != SOCKS5_VER || method_resp[1] != SOCKS5_METHOD_NO_AUTH) {
        closesocket(sock);
        return -1;
    }

    unsigned char req_buf[4 + 256 + 2];
    size_t req_len;

    req_buf[0] = SOCKS5_VER;
    req_buf[1] = SOCKS5_CMD_CONNECT;
    req_buf[2] = 0x00;

    uint32_t ip = inet_addr(target_host);
    if (ip != INADDR_NONE) {
        req_buf[3] = SOCKS5_ATYP_IPV4;
        memcpy(req_buf + 4, &ip, 4);
        req_len = 8;
    } else {
        size_t dlen = strlen(target_host);
        if (dlen > 255) {
            closesocket(sock);
            return -1;
        }
        req_buf[3] = SOCKS5_ATYP_DOMAIN;
        req_buf[4] = (unsigned char)dlen;
        memcpy(req_buf + 5, target_host, dlen);
        req_len = 5 + dlen;
    }

    req_buf[req_len]     = (unsigned char)((target_port >> 8) & 0xff);
    req_buf[req_len + 1] = (unsigned char)(target_port & 0xff);
    req_len += 2;

    if (socks5_send_all(sock, req_buf, req_len) != 0) {
        closesocket(sock);
        return -1;
    }

    unsigned char resp_header[4];
    if (socks5_recv_all(sock, resp_header, 4) != 0) {
        closesocket(sock);
        return -1;
    }

    if (resp_header[0] != SOCKS5_VER || resp_header[1] != SOCKS5_REP_SUCCESS) {
        closesocket(sock);
        return -1;
    }

    unsigned char atyp = resp_header[3];
    unsigned char addr_buf[256];
    size_t addr_len = 0;

    switch (atyp) {
    case SOCKS5_ATYP_IPV4:
        addr_len = 4;
        break;
    case SOCKS5_ATYP_DOMAIN:
        if (socks5_recv_all(sock, addr_buf, 1) != 0) {
            closesocket(sock);
            return -1;
        }
        addr_len = 1 + addr_buf[0];
        break;
    default:
        closesocket(sock);
        return -1;
    }

    if (addr_len > 0) {
        if (socks5_recv_all(sock, addr_buf, addr_len) != 0) {
            closesocket(sock);
            return -1;
        }
    }

    unsigned char port_buf[2];
    if (socks5_recv_all(sock, port_buf, 2) != 0) {
        closesocket(sock);
        return -1;
    }

    *out_sock = sock;
    return 0;
}

const char *socks5_resolve_via_tor(void) {
    return "127.0.0.1";
}

#endif /* ENABLE_SOCKS5 */
