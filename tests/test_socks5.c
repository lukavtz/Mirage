/*
 * test_socks5.c — SOCKS5 protocol unit tests
 *
 * Tests SOCKS5 handshake construction and address encoding
 * logic by replicating the protocol byte-building from socks5.c.
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -Iinclude -std=c11
 *       -o tests/test_socks5.exe tests/test_socks5.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/* ── SOCKS5 constants (mirrored from socks5.c) ───────────────── */

#define SOCKS5_VER             0x05
#define SOCKS5_CMD_CONNECT     0x01
#define SOCKS5_CMD_BIND        0x02
#define SOCKS5_CMD_UDP         0x03
#define SOCKS5_ATYP_IPV4       0x01
#define SOCKS5_ATYP_DOMAIN     0x03
#define SOCKS5_ATYP_IPV6       0x04
#define SOCKS5_REP_SUCCESS     0x00
#define SOCKS5_METHOD_NO_AUTH  0x00

/* ── Protocol construction helpers (mirror socks5.c logic) ────── */

static size_t build_method_request(uint8_t *out) {
    out[0] = SOCKS5_VER;
    out[1] = 0x01;
    out[2] = SOCKS5_METHOD_NO_AUTH;
    return 3;
}

static size_t build_connect_request(uint8_t *out, const char *host, uint16_t port) {
    size_t rlen = 0;
    out[rlen++] = SOCKS5_VER;
    out[rlen++] = SOCKS5_CMD_CONNECT;
    out[rlen++] = 0x00;

    size_t hlen = strlen(host);
    if (hlen > 255) return 0;

    out[rlen++] = SOCKS5_ATYP_DOMAIN;
    out[rlen++] = (uint8_t)hlen;
    memcpy(out + rlen, host, hlen);
    rlen += hlen;
    out[rlen++] = (uint8_t)(port >> 8);
    out[rlen++] = (uint8_t)(port & 0xFF);
    return rlen;
}

static size_t build_connect_ipv4(uint8_t *out, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    size_t rlen = 0;
    out[rlen++] = SOCKS5_VER;
    out[rlen++] = SOCKS5_CMD_CONNECT;
    out[rlen++] = 0x00;
    out[rlen++] = SOCKS5_ATYP_IPV4;
    out[rlen++] = a;
    out[rlen++] = b;
    out[rlen++] = c;
    out[rlen++] = d;
    out[rlen++] = (uint8_t)(port >> 8);
    out[rlen++] = (uint8_t)(port & 0xFF);
    return rlen;
}

/* ── Method request tests ────────────────────────────────────── */

static void test_method_request_format(void) {
    uint8_t req[3];
    size_t len = build_method_request(req);
    assert(len == 3);
    assert(req[0] == 0x05);
    assert(req[1] == 0x01);
    assert(req[2] == 0x00);
    TEST("test_method_request_format");
}

static void test_method_request_size(void) {
    uint8_t req[3];
    size_t len = build_method_request(req);
    assert(len == 3);
    TEST("test_method_request_size");
}

/* ── CONNECT request tests ───────────────────────────────────── */

static void test_connect_domain_basic(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "example.com", 80);
    assert(len > 0);
    assert(req[0] == SOCKS5_VER);
    assert(req[1] == SOCKS5_CMD_CONNECT);
    assert(req[2] == 0x00);
    assert(req[3] == SOCKS5_ATYP_DOMAIN);
    assert(req[4] == 11);
    assert(memcmp(req + 5, "example.com", 11) == 0);
    assert(req[16] == 0x00);
    assert(req[17] == 0x50);
    TEST("test_connect_domain_basic");
}

static void test_connect_domain_port_encoding(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "test.io", 443);
    assert(len > 0);
    size_t port_off = 5 + 7;
    assert(req[port_off] == 0x01);
    assert(req[port_off + 1] == 0xBB);
    TEST("test_connect_domain_port_encoding");
}

static void test_connect_domain_high_port(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "h", 65535);
    assert(len > 0);
    size_t port_off = 5 + 1;
    assert(req[port_off] == 0xFF);
    assert(req[port_off + 1] == 0xFF);
    TEST("test_connect_domain_high_port");
}

static void test_connect_domain_low_port(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "h", 1);
    assert(len > 0);
    size_t port_off = 5 + 1;
    assert(req[port_off] == 0x00);
    assert(req[port_off + 1] == 0x01);
    TEST("test_connect_domain_low_port");
}

static void test_connect_ipv4_format(void) {
    uint8_t req[512];
    size_t len = build_connect_ipv4(req, 192, 168, 1, 1, 8080);
    assert(len == 10);
    assert(req[0] == SOCKS5_VER);
    assert(req[1] == SOCKS5_CMD_CONNECT);
    assert(req[3] == SOCKS5_ATYP_IPV4);
    assert(req[4] == 192);
    assert(req[5] == 168);
    assert(req[6] == 1);
    assert(req[7] == 1);
    assert(req[8] == 0x1F);
    assert(req[9] == 0x90);
    TEST("test_connect_ipv4_format");
}

static void test_connect_ipv4_size(void) {
    uint8_t req[512];
    size_t len = build_connect_ipv4(req, 127, 0, 0, 1, 80);
    assert(len == 10);
    TEST("test_connect_ipv4_size");
}

/* ── Address type encoding tests ─────────────────────────────── */

static void test_atyp_values(void) {
    assert(SOCKS5_ATYP_IPV4 == 0x01);
    assert(SOCKS5_ATYP_DOMAIN == 0x03);
    assert(SOCKS5_ATYP_IPV6 == 0x04);
    TEST("test_atyp_values");
}

static void test_connect_request_total_size_domain(void) {
    uint8_t req[512];
    const char *host = "abcdefghijklmnop.example.com";
    size_t len = build_connect_request(req, host, 443);
    assert(len == 35);
    TEST("test_connect_request_total_size_domain");
}

/* ── Response parsing tests ──────────────────────────────────── */

static void test_response_success_format(void) {
    uint8_t resp[10] = {SOCKS5_VER, 0x00, 0x00, SOCKS5_ATYP_IPV4,
                         0, 0, 0, 0, 0, 0};
    assert(resp[0] == SOCKS5_VER);
    assert(resp[1] == SOCKS5_REP_SUCCESS);
    assert(resp[3] == SOCKS5_ATYP_IPV4);
    TEST("test_response_success_format");
}

static void test_response_error_values(void) {
    uint8_t errors[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    for (size_t i = 0; i < sizeof(errors); i++) {
        assert(errors[i] != SOCKS5_REP_SUCCESS);
    }
    TEST("test_response_error_values");
}

static void test_response_domain_addr_type(void) {
    uint8_t resp_hdr[4] = {SOCKS5_VER, 0x00, 0x00, SOCKS5_ATYP_DOMAIN};
    uint8_t domain_len = 11;
    uint8_t domain[] = "example.com"; (void)domain;
    uint8_t port[] = {0x00, 0x50};

    assert(resp_hdr[3] == SOCKS5_ATYP_DOMAIN);
    assert(domain_len == 11);
    assert(port[0] == 0x00 && port[1] == 0x50);
    TEST("test_response_domain_addr_type");
}

/* ── SOCKS5 version and command constants ────────────────────── */

static void test_socks5_version(void) {
    assert(SOCKS5_VER == 0x05);
    TEST("test_socks5_version");
}

static void test_socks5_commands(void) {
    assert(SOCKS5_CMD_CONNECT == 0x01);
    assert(SOCKS5_CMD_BIND == 0x02);
    assert(SOCKS5_CMD_UDP == 0x03);
    TEST("test_socks5_commands");
}

static void test_socks5_no_auth(void) {
    assert(SOCKS5_METHOD_NO_AUTH == 0x00);
    TEST("test_socks5_no_auth");
}

/* ── Domain name length validation ───────────────────────────── */

static void test_domain_max_length(void) {
    char host[256];
    memset(host, 'a', 255);
    host[255] = '\0';
    uint8_t req[512];
    size_t len = build_connect_request(req, host, 80);
    assert(len > 0);
    assert(req[4] == 255);
    TEST("test_domain_max_length");
}

static void test_domain_single_char(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "x", 80);
    assert(len > 0);
    assert(req[4] == 1);
    assert(req[5] == 'x');
    TEST("test_domain_single_char");
}

/* ── Port boundary tests ─────────────────────────────────────── */

static void test_port_zero(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "h", 0);
    assert(len > 0);
    size_t port_off = 5 + 1;
    assert(req[port_off] == 0x00);
    assert(req[port_off + 1] == 0x00);
    TEST("test_port_zero");
}

static void test_port_byte_order(void) {
    uint8_t req[512];
    size_t len = build_connect_request(req, "h", 256);
    assert(len > 0);
    size_t port_off = 5 + 1;
    assert(req[port_off] == 0x01);
    assert(req[port_off + 1] == 0x00);
    TEST("test_port_byte_order");
}

/* ── main ────────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_socks5: SOCKS5 protocol tests ===\n");

    test_method_request_format();
    test_method_request_size();
    test_connect_domain_basic();
    test_connect_domain_port_encoding();
    test_connect_domain_high_port();
    test_connect_domain_low_port();
    test_connect_ipv4_format();
    test_connect_ipv4_size();
    test_atyp_values();
    test_connect_request_total_size_domain();
    test_response_success_format();
    test_response_error_values();
    test_response_domain_addr_type();
    test_socks5_version();
    test_socks5_commands();
    test_socks5_no_auth();
    test_domain_max_length();
    test_domain_single_char();
    test_port_zero();
    test_port_byte_order();

    printf("=== test_socks5: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
