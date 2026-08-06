/*
 * test_proxy.c — proxy_parse_c2 C2 address parsing tests
 *
 * Tests the proxy_parse_c2 function with valid/invalid c2://host:port strings.
 * Replicates the parse_c2_address logic for standalone testing.
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_proxy.exe tests/test_proxy.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int passed = 0, failed = 0;
#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)

typedef enum {
    PROXY_TELEGRAM = 1, PROXY_TON = 2, PROXY_STEAM = 3,
    PROXY_GITHUB = 4, PROXY_VPS = 5,
} proxy_level_t;

typedef struct {
    const char    *c2_host;
    uint16_t       c2_port;
    proxy_level_t  level;
} proxy_result_t;

static int parse_c2_address(const char *c2_str, size_t len, proxy_result_t *out) {
    size_t colon = 0; int found = 0;
    for (size_t i = 0; i < len; ++i) {
        if (c2_str[i] == ':') { colon = i; found = 1; break; }
    }
    if (!found || colon == 0 || colon >= len - 1) return 0;
    size_t host_len = colon;
    if (host_len > 255) return 0;
    for (size_t i = 0; i < host_len; ++i) {
        char c = c2_str[i];
        if (c != '.' && (c < '0' || c > '9')) return 0;
    }
    char port_buf[8];
    size_t plen = len - colon - 1;
    if (plen == 0 || plen >= sizeof(port_buf)) return 0;
    memcpy(port_buf, c2_str + colon + 1, plen);
    port_buf[plen] = '\0';
    long port = strtol(port_buf, NULL, 10);
    if (port <= 0 || port > 65535) return 0;
    char *host = malloc(host_len + 1);
    if (!host) return 0;
    memcpy(host, c2_str, host_len);
    host[host_len] = '\0';
    out->c2_host = host;
    out->c2_port = (uint16_t)port;
    out->level   = PROXY_GITHUB;
    return 1;
}

static int proxy_parse_c2(const char *body, size_t body_len, proxy_result_t *out) {
    if (!body || body_len == 0 || !out) return 0;
    const char *prefix = "c2://";
    size_t plen = strlen(prefix);
    for (size_t i = 0; i + plen < body_len; ++i) {
        if (memcmp(body + i, prefix, plen) == 0) {
            const char *addr = body + i + plen;
            size_t remaining = body_len - i - plen;
            size_t alen = 0;
            for (size_t j = 0; j < remaining; ++j) {
                char c = addr[j];
                if (c == '\0' || c == '\r' || c == '\n' || c == ' ' || c == '\t') break;
                alen++;
            }
            if (alen == 0) continue;
            if (parse_c2_address(addr, alen, out)) return 1;
        }
    }
    return 0;
}

static void test_valid_basic(void) {
    proxy_result_t out = {0};
    int r = proxy_parse_c2("c2://1.2.3.4:8080", 17, &out);
    assert(r == 1);
    assert(out.c2_port == 8080);
    assert(strcmp(out.c2_host, "1.2.3.4") == 0);
    assert(out.level == PROXY_GITHUB);
    free((void*)out.c2_host);
    TEST("test_valid_basic");
}

static void test_valid_embedded(void) {
    const char *body = "some data\nc2://192.168.1.1:443\nmore";
    proxy_result_t out = {0};
    int r = proxy_parse_c2(body, strlen(body), &out);
    assert(r == 1);
    assert(out.c2_port == 443);
    assert(strcmp(out.c2_host, "192.168.1.1") == 0);
    free((void*)out.c2_host);
    TEST("test_valid_embedded");
}

static void test_valid_port_1(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://10.0.0.1:1", 16, &out) == 1);
    assert(out.c2_port == 1);
    free((void*)out.c2_host);
    TEST("test_valid_port_1");
}

static void test_valid_port_65535(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://10.0.0.1:65535", 19, &out) == 1);
    assert(out.c2_port == 65535);
    free((void*)out.c2_host);
    TEST("test_valid_port_65535");
}

static void test_valid_loopback(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://127.0.0.1:9999", 19, &out) == 1);
    assert(out.c2_port == 9999);
    assert(strcmp(out.c2_host, "127.0.0.1") == 0);
    free((void*)out.c2_host);
    TEST("test_valid_loopback");
}

static void test_invalid_no_prefix(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("http://1.2.3.4:80", 17, &out) == 0);
    TEST("test_invalid_no_prefix");
}

static void test_invalid_no_port(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4", 13, &out) == 0);
    TEST("test_invalid_no_port");
}

static void test_invalid_port_zero(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4:0", 14, &out) == 0);
    TEST("test_invalid_port_zero");
}

static void test_invalid_port_over(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4:65536", 18, &out) == 0);
    TEST("test_invalid_port_over");
}

static void test_invalid_neg_port(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4:-1", 15, &out) == 0);
    TEST("test_invalid_neg_port");
}

static void test_invalid_empty_body(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("", 0, &out) == 0);
    TEST("test_invalid_empty_body");
}

static void test_invalid_null_body(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2(NULL, 10, &out) == 0);
    TEST("test_invalid_null_body");
}

static void test_invalid_null_out(void) {
    assert(proxy_parse_c2("c2://1.2.3.4:80", 15, NULL) == 0);
    TEST("test_invalid_null_out");
}

static void test_invalid_host_letters(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://example.com:80", 19, &out) == 0);
    TEST("test_invalid_host_letters");
}

static void test_invalid_empty_host(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://:80", 8, &out) == 0);
    TEST("test_invalid_empty_host");
}

static void test_invalid_empty_port(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4:", 14, &out) == 0);
    TEST("test_invalid_empty_port");
}

static void test_invalid_port_alpha(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://1.2.3.4:abc", 16, &out) == 0);
    TEST("test_invalid_port_alpha");
}

static void test_invalid_just_prefix(void) {
    proxy_result_t out = {0};
    assert(proxy_parse_c2("c2://", 5, &out) == 0);
    TEST("test_invalid_just_prefix");
}

static void test_multiple_c2_prefixes(void) {
    const char *body = "c2://bad\nc2://10.0.0.1:443";
    proxy_result_t out = {0};
    int r = proxy_parse_c2(body, strlen(body), &out);
    assert(r == 1);
    assert(out.c2_port == 443);
    assert(strcmp(out.c2_host, "10.0.0.1") == 0);
    free((void*)out.c2_host);
    TEST("test_multiple_c2_prefixes");
}

static void test_host_max_length(void) {
    char buf[512];
    memcpy(buf, "c2://", 5);
    memset(buf + 5, '1', 255);
    memcpy(buf + 260, ":80", 3);
    proxy_result_t out = {0};
    int r = proxy_parse_c2(buf, 263, &out);
    assert(r == 1);
    assert(strlen(out.c2_host) == 255);
    assert(out.c2_port == 80);
    free((void*)out.c2_host);
    TEST("test_host_max_length");
}

static void test_host_too_long(void) {
    char buf[512];
    memcpy(buf, "c2://", 5);
    memset(buf + 5, '1', 256);
    memcpy(buf + 261, ":80", 3);
    proxy_result_t out = {0};
    assert(proxy_parse_c2(buf, 264, &out) == 0);
    TEST("test_host_too_long");
}

int main(void) {
    printf("=== test_proxy: proxy_parse_c2 tests ===\n");
    test_valid_basic(); test_valid_embedded(); test_valid_port_1();
    test_valid_port_65535(); test_valid_loopback();
    test_invalid_no_prefix(); test_invalid_no_port(); test_invalid_port_zero();
    test_invalid_port_over(); test_invalid_neg_port(); test_invalid_empty_body();
    test_invalid_null_body(); test_invalid_null_out(); test_invalid_host_letters();
    test_invalid_empty_host(); test_invalid_empty_port(); test_invalid_port_alpha();
    test_invalid_just_prefix(); test_multiple_c2_prefixes();
    test_host_max_length(); test_host_too_long();
    printf("=== test_proxy: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
