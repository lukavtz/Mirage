/*
 * test_network_mock.c -- Network tests via ws2 mock seam
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc -Isrc/network -Isrc/crypto -Isrc/types \
 *        -Isrc/utils -Isrc/parsers -std=c11 -DZIALFI_TEST_MODE \
 *        -o tests/test_network_mock tests/test_network_mock.c \
 *        src/network/ws2.c src/network/ws2_peb.c src/types/hash.c \
 *        src/types/export_resolve.c src/types/peb.c -lws2_32
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZIALFI_TEST_MODE
#include <winsock2.h>
#include <windows.h>
#include "ws2.h"
#include "ws2_peb.h"

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/* Stub for NASM getPeb */
void *getPeb(void) { return NULL; }

/* ── Mock state ─────────────────────────────────────────────── */
static int g_send_call_count = 0;
static int g_send_fails_at = -1;  /* -1 = never fail */
static int g_recv_returns_eagain = 0;
static const char *g_recv_data = NULL;
static size_t g_recv_data_len = 0;

static int WSAAPI mock_send(SOCKET s, const char *buf, int len, int flags) {
    (void)s; (void)flags;
    g_send_call_count++;
    if (g_send_fails_at >= 0 && g_send_call_count >= g_send_fails_at) return -1;
    /* Return partial: 500 bytes at a time to exercise the send loop */
    return len > 500 ? 500 : len;
}

static int WSAAPI mock_recv(SOCKET s, char *buf, int len, int flags) {
    (void)s; (void)flags;
    if (g_recv_returns_eagain) {
        /* Simulate EAGAIN/timeout */
        return -1;
    }
    if (g_recv_data && g_recv_data_len > 0) {
        size_t copy = (size_t)len < g_recv_data_len ? (size_t)len : g_recv_data_len;
        memcpy(buf, g_recv_data, copy);
        return (int)copy;
    }
    return 0;
}

static int WSAAPI mock_startup(WORD a, LPWSADATA b) { (void)a;(void)b; return 0; }
static int WSAAPI mock_cleanup(void) { return 0; }
static SOCKET WSAAPI mock_socket(int a, int b, int c, LPWSAPROTOCOL_INFOW d, GROUP e, DWORD f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 1; }
static int WSAAPI mock_connect(SOCKET a, const struct sockaddr *b, int c) { (void)a;(void)b;(void)c; return 0; }
static int WSAAPI mock_closesocket(SOCKET a) { (void)a; return 0; }
static int WSAAPI mock_bind(SOCKET a, const struct sockaddr *b, int c) { (void)a;(void)b;(void)c; return 0; }
static int WSAAPI mock_listen(SOCKET a, int b) { (void)a;(void)b; return 0; }
static SOCKET WSAAPI mock_accept(SOCKET a, struct sockaddr *b, int *c) { (void)a;(void)b;(void)c; return 1; }
static int WSAAPI mock_setsockopt(SOCKET a, int b, int c, const char *d, int e) { (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
static int WSAAPI mock_getsockname(SOCKET a, struct sockaddr *b, int *c) { (void)a;(void)b;(void)c; return 0; }
static u_short WSAAPI mock_htons(u_short a) { return a; }
static u_long WSAAPI mock_htonl(u_long a) { return a; }
static u_short WSAAPI mock_ntohs(u_short a) { return a; }

static void install_mock_ws2(void) {
    ws2_api_t mock = {0};
    mock.pStartup = mock_startup; mock.pCleanup = mock_cleanup;
    mock.pWSASocketW = mock_socket; mock.pconnect = mock_connect;
    mock.psend = mock_send; mock.precv = mock_recv;
    mock.pclosesocket = mock_closesocket; mock.pbind = mock_bind;
    mock.plisten = mock_listen; mock.paccept = mock_accept;
    mock.psetsockopt = mock_setsockopt; mock.pgetsockname = mock_getsockname;
    mock.phtons = mock_htons; mock.phtonl = mock_htonl; mock.pntohs = mock_ntohs;
    mirage_ws2_api_install(&mock);
}

int main(void) {
    int passed = 0, failed = 0;
    printf("=== test_network_mock: Network mock tests ===\n");

    install_mock_ws2();

    /* Test 1: ws2_connect succeeds with mock */
    {
        ws2_socket_t sock;
        ws2_result_t r = ws2_connect(&sock, "127.0.0.1", 80);
        if (r == WS2_OK) TEST("ws2_connect success");
        else { char m[64]; snprintf(m,64,"rc=%d", r); FAIL("ws2_connect", m); }
        ws2_close(sock.handle);
    }

    /* Test 2: ws2_send full send */
    {
        g_send_call_count = 0;
        g_send_fails_at = -1;
        uint8_t data[100]; memset(data, 'A', 100);
        size_t sent = 0;
        ws2_result_t r = ws2_send((HANDLE)1, data, 100, &sent);
        if (r == WS2_OK && sent == 100) TEST("ws2_send full");
        else FAIL("ws2_send full", "unexpected result");
    }

    /* Test 3: ws2_send partial then fail */
    {
        g_send_call_count = 0;
        g_send_fails_at = 2;  /* fail on 2nd call */
        uint8_t data[1000]; memset(data, 'B', 1000);
        size_t sent = 0;
        ws2_result_t r = ws2_send((HANDLE)1, data, 1000, &sent);
        if (r == WS2_ERR_SEND_FAILED) TEST("ws2_send partial fail");
        else FAIL("ws2_send partial fail", "unexpected result");
    }

    /* Test 4: ws2_recv with data */
    {
        g_recv_returns_eagain = 0;
        g_recv_data = "HTTP/1.1 200 OK\r\n";
        g_recv_data_len = 18;
        uint8_t buf[256] = {0};
        size_t read = 0;
        ws2_result_t r = ws2_recv((HANDLE)1, buf, sizeof(buf), &read);
        if (r == WS2_OK && read == 18 && memcmp(buf, "HTTP/1.1 200 OK\r\n", 18) == 0)
            TEST("ws2_recv with data");
        else FAIL("ws2_recv with data", "wrong data or length");
    }

    /* Test 5: ws2_recv timeout (EAGAIN) */
    {
        g_recv_returns_eagain = 1;
        uint8_t buf[256] = {0};
        size_t read = 0;
        ws2_result_t r = ws2_recv((HANDLE)1, buf, sizeof(buf), &read);
        #ifdef _WIN32
        if (r == WS2_ERR_RECV_FAILED) TEST("ws2_recv timeout returns error (Windows)");
#else
        if (r == WS2_OK && read == 0) TEST("ws2_recv timeout returns WS2_OK with 0 bytes (POSIX)");
#endif
        else FAIL("ws2_recv timeout", "unexpected result");
        g_recv_returns_eagain = 0;
    }

    /* Test 6: ws2_recv zero-length */
    {
        uint8_t buf[1] = {0};
        size_t read = 99;
        ws2_result_t r = ws2_recv((HANDLE)1, buf, 0, &read);
        if (r == WS2_OK && read == 0) TEST("ws2_recv zero-length");
        else FAIL("ws2_recv zero-length", "unexpected result");
    }

    /* Test 7: ws2_send zero-length */
    {
        size_t sent = 99;
        ws2_result_t r = ws2_send((HANDLE)1, NULL, 0, &sent);
        if (r == WS2_OK && sent == 0) TEST("ws2_send zero-length");
        else FAIL("ws2_send zero-length", "unexpected result");
    }

    printf("=== test_network_mock: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
