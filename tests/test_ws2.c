/*
 * test_ws2.c — WS2 network module unit tests
 *
 * Tests: ws2_parse_ipv4 (pure C), ws2_init/cleanup, ws2_send/recv (mock).
 *
 * Build (Windows):
 *   gcc -Wall -Wextra -O2 -Wno-error -Wno-cpp -Iinclude -Isrc -Isrc/network
 *       -Isrc/types -Isrc/utils -Isrc/parsers -std=c11 -DZIALFI_TEST_MODE
 *       -o tests/test_ws2.exe tests/test_ws2.c src/network/ws2.c
 *       src/network/ws2_peb.c src/types/hash.c src/types/export_resolve.c
 *       src/types/peb.c -lws2_32
 *
 * Build (Linux):
 *   gcc -Wall -Wextra -O2 -Iinclude -Isrc -Isrc/network -std=c11
 *       -o tests/test_ws2 tests/test_ws2.c src/network/ws2.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ws2.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ws2_peb.h"

void *getPeb(void) { return NULL; }

static int WSAAPI mock_startup(WORD a, LPWSADATA b) { (void)a;(void)b; return 0; }
static int WSAAPI mock_cleanup(void) { return 0; }
static SOCKET WSAAPI mock_socket(int a, int b, int c, LPWSAPROTOCOL_INFOW d, GROUP e, DWORD f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 1;
}
static int WSAAPI mock_connect(SOCKET a, const struct sockaddr *b, int c) { (void)a;(void)b;(void)c; return 0; }
static int WSAAPI mock_send(SOCKET s, const char *buf, int len, int flags) { (void)s;(void)buf;(void)flags; return len; }
static int WSAAPI mock_recv(SOCKET s, char *buf, int len, int flags) { (void)s;(void)buf;(void)len;(void)flags; return 0; }
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
#endif

static int passed = 0, failed = 0;
#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/* ── ws2_parse_ipv4 tests ────────────────────────────────────── */

static void test_ipv4_basic(void) {
    uint32_t ip = ws2_parse_ipv4("127.0.0.1");
    assert(ip != 0);
    const uint8_t *bytes = (const uint8_t *)&ip;
    assert(bytes[0] == 127);
    assert(bytes[1] == 0);
    assert(bytes[2] == 0);
    assert(bytes[3] == 1);
    TEST("test_ipv4_basic");
}

static void test_ipv4_all_zeros(void) {
    uint32_t ip = ws2_parse_ipv4("0.0.0.0");
    const uint8_t *bytes = (const uint8_t *)&ip;
    assert(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0);
    TEST("test_ipv4_all_zeros");
}

static void test_ipv4_max_values(void) {
    uint32_t ip = ws2_parse_ipv4("255.255.255.255");
    const uint8_t *bytes = (const uint8_t *)&ip;
    assert(bytes[0] == 255 && bytes[1] == 255 &&
           bytes[2] == 255 && bytes[3] == 255);
    TEST("test_ipv4_max_values");
}

static void test_ipv4_octet_overflow(void) {
    assert(ws2_parse_ipv4("256.1.1.1") == 0);
    TEST("test_ipv4_octet_overflow");
}

static void test_ipv4_too_few_octets(void) {
    assert(ws2_parse_ipv4("1.2.3") == 0);
    assert(ws2_parse_ipv4("1.2") == 0);
    assert(ws2_parse_ipv4("1") == 0);
    TEST("test_ipv4_too_few_octets");
}

static void test_ipv4_too_many_octets(void) {
    assert(ws2_parse_ipv4("1.2.3.4.5") == 0);
    TEST("test_ipv4_too_many_octets");
}

static void test_ipv4_non_numeric(void) {
    assert(ws2_parse_ipv4("abc.def.ghi.jkl") == 0);
    assert(ws2_parse_ipv4("1.2.3.4a") == 0);
    TEST("test_ipv4_non_numeric");
}

static void test_ipv4_empty_string(void) {
    assert(ws2_parse_ipv4("") == 0);
    TEST("test_ipv4_empty_string");
}

static void test_ipv4_leading_dot(void) {
    assert(ws2_parse_ipv4(".1.2.3.4") == 0);
    TEST("test_ipv4_leading_dot");
}

static void test_ipv4_trailing_dot(void) {
    assert(ws2_parse_ipv4("1.2.3.4.") == 0);
    TEST("test_ipv4_trailing_dot");
}

static void test_ipv4_consecutive_dots(void) {
    assert(ws2_parse_ipv4("1..2.3.4") == 0);
    TEST("test_ipv4_consecutive_dots");
}

static void test_ipv4_loopback_order(void) {
    uint32_t ip = ws2_parse_ipv4("127.0.0.1");
    assert(ip != 0);
    union { uint32_t u; uint8_t b[4]; } v;
    v.u = ip;
    assert(v.b[0] == 127);
    assert(v.b[3] == 1);
    TEST("test_ipv4_loopback_order");
}

static void test_ipv4_common_addresses(void) {
    uint32_t ip1 = ws2_parse_ipv4("192.168.1.1");
    assert(ip1 != 0);
    const uint8_t *b1 = (const uint8_t *)&ip1;
    assert(b1[0] == 192 && b1[1] == 168 && b1[2] == 1 && b1[3] == 1);
    uint32_t ip2 = ws2_parse_ipv4("10.0.0.1");
    assert(ip2 != 0);
    const uint8_t *b2 = (const uint8_t *)&ip2;
    assert(b2[0] == 10 && b2[1] == 0 && b2[2] == 0 && b2[3] == 1);
    TEST("test_ipv4_common_addresses");
}

static void test_ipv4_single_digit(void) {
    uint32_t ip = ws2_parse_ipv4("1.2.3.4");
    assert(ip != 0);
    const uint8_t *b = (const uint8_t *)&ip;
    assert(b[0] == 1 && b[1] == 2 && b[2] == 3 && b[3] == 4);
    TEST("test_ipv4_single_digit");
}

/* ── ws2_init / ws2_cleanup tests ────────────────────────────── */

static void test_ws2_init_succeeds(void) {
    ws2_result_t r = ws2_init();
    assert(r == WS2_OK);
    TEST("test_ws2_init_succeeds");
}

static void test_ws2_init_idempotent(void) {
    ws2_result_t r1 = ws2_init();
    ws2_result_t r2 = ws2_init();
    assert(r1 == WS2_OK);
    assert(r2 == WS2_OK);
    TEST("test_ws2_init_idempotent");
}

static void test_ws2_cleanup_succeeds(void) {
    ws2_init();
    ws2_cleanup();
    ws2_cleanup();
    TEST("test_ws2_cleanup_succeeds");
}

static void test_ws2_reinit_after_cleanup(void) {
    ws2_init();
    ws2_cleanup();
    ws2_result_t r = ws2_init();
    assert(r == WS2_OK);
    ws2_cleanup();
    TEST("test_ws2_reinit_after_cleanup");
}

/* ── ws2_send / ws2_recv edge cases ──────────────────────────── */

static void test_ws2_send_null_data(void) {
    size_t sent = 99;
    ws2_result_t r = ws2_send((HANDLE)1, NULL, 0, &sent);
    assert(r == WS2_OK);
    assert(sent == 0);
    TEST("test_ws2_send_null_data");
}

static void test_ws2_send_zero_len(void) {
    uint8_t data[10];
    size_t sent = 99;
    ws2_result_t r = ws2_send((HANDLE)1, data, 0, &sent);
    assert(r == WS2_OK);
    assert(sent == 0);
    TEST("test_ws2_send_zero_len");
}

static void test_ws2_recv_null_buf(void) {
    size_t readn = 99;
    ws2_result_t r = ws2_recv((HANDLE)1, NULL, 0, &readn);
    assert(r == WS2_OK);
    assert(readn == 0);
    TEST("test_ws2_recv_null_buf");
}

static void test_ws2_recv_zero_len(void) {
    uint8_t buf[10];
    size_t readn = 99;
    ws2_result_t r = ws2_recv((HANDLE)1, buf, 0, &readn);
    assert(r == WS2_OK);
    assert(readn == 0);
    TEST("test_ws2_recv_zero_len");
}

static void test_ws2_close_null(void) {
    ws2_close(NULL);
    TEST("test_ws2_close_null");
}

static void test_result_enums(void) {
    assert(WS2_OK == 0);
    assert(WS2_ERR_INIT_FAILED != WS2_OK);
    assert(WS2_ERR_SOCKET_FAILED != WS2_OK);
    assert(WS2_ERR_CONNECT_FAILED != WS2_OK);
    assert(WS2_ERR_RESOLVE_FAILED != WS2_OK);
    assert(WS2_ERR_SEND_FAILED != WS2_OK);
    assert(WS2_ERR_RECV_FAILED != WS2_OK);
    TEST("test_result_enums");
}

/* ── main ────────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_ws2: WS2 network module tests ===\n");

#ifdef _WIN32
    install_mock_ws2();
#endif

    test_ipv4_basic();
    test_ipv4_all_zeros();
    test_ipv4_max_values();
    test_ipv4_octet_overflow();
    test_ipv4_too_few_octets();
    test_ipv4_too_many_octets();
    test_ipv4_non_numeric();
    test_ipv4_empty_string();
    test_ipv4_leading_dot();
    test_ipv4_trailing_dot();
    test_ipv4_consecutive_dots();
    test_ipv4_loopback_order();
    test_ipv4_common_addresses();
    test_ipv4_single_digit();

    test_ws2_init_succeeds();
    test_ws2_init_idempotent();
    test_ws2_cleanup_succeeds();
    test_ws2_reinit_after_cleanup();

    test_ws2_send_null_data();
    test_ws2_send_zero_len();
    test_ws2_recv_null_buf();
    test_ws2_recv_zero_len();
    test_ws2_close_null();
    test_result_enums();

    printf("=== test_ws2: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
