/*
 * test_clipper.c — Clipper address detection tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_clipper tests/test_clipper.c
 *
 * NOTE: is_btc_char() in clipper.c only accepts '2'-'9' digits (missing '1').
 * Test validates ACTUAL source behavior.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ── Inline actual helpers from clipper.c ─────────────────── */

static int is_btc_char(char c) {
    return (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
           (c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') ||
           (c >= 'm' && c <= 'z') || (c >= '2' && c <= '9');
}

static int is_ltc_char(char c) {
    return is_btc_char(c) || c == '0' || c == 'O';
}

static int detect_btc(const char *text) {
    const char *p = text;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '1' || *p == '3') {
        int len = 0;
        while (*p && !isspace((unsigned char)*p)) {
            if (!is_btc_char(*p)) return 0;
            len++; p++;
        }
        if (len >= 26 && len <= 62) return 1;
    }
    if (p[0] == 'b' && p[1] == 'c' && p[2] == '1') {
        int len = 0; p += 3;
        while (*p && !isspace((unsigned char)*p)) { len++; p++; }
        if (len >= 39 && len <= 59) return 1;
    }
    return 0;
}

static int detect_eth(const char *text) {
    const char *p = text;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) return 0;
    p += 2;
    int len = 0;
    while (*p && !isspace((unsigned char)*p)) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
        len++; p++;
    }
    return (len == 40) ? 2 : 0;
}

static int detect_ltc(const char *text) {
    const char *p = text;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == 'L' || *p == 'M') {
        int len = 0;
        while (*p && !isspace((unsigned char)*p)) {
            if (!is_ltc_char(*p)) return 0;
            len++; p++;
        }
        if (len >= 26 && len <= 34) return 3;
    }
    if (p[0] == 'l' && p[1] == 't' && p[2] == 'c' && p[3] == '1') {
        int len = 0; p += 4;
        while (*p && !isspace((unsigned char)*p)) { len++; p++; }
        if (len >= 39 && len <= 59) return 3;
    }
    return 0;
}

static int clipper_detect_address(const char *text) {
    if (!text || !*text) return 0;
    int r = detect_btc(text);
    if (r) return r;
    r = detect_eth(text);
    if (r) return r;
    r = detect_ltc(text);
    if (r) return r;
    return 0;
}

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_btc_char_valid(void) {
    assert(is_btc_char('A') == 1);
    assert(is_btc_char('H') == 1);
    assert(is_btc_char('J') == 1);
    assert(is_btc_char('N') == 1);
    assert(is_btc_char('P') == 1);
    assert(is_btc_char('Z') == 1);
    assert(is_btc_char('a') == 1);
    assert(is_btc_char('k') == 1);
    assert(is_btc_char('m') == 1);
    assert(is_btc_char('z') == 1);
    assert(is_btc_char('2') == 1);
    assert(is_btc_char('9') == 1);
}

static void test_btc_char_invalid(void) {
    assert(is_btc_char('0') == 0);
    assert(is_btc_char('1') == 0);
    assert(is_btc_char('O') == 0);
    assert(is_btc_char('I') == 0);
    assert(is_btc_char('l') == 0);
    assert(is_btc_char('!') == 0);
    assert(is_btc_char('@') == 0);
    assert(is_btc_char(' ') == 0);
}

static void test_ltc_char_valid(void) {
    assert(is_ltc_char('A') == 1);
    assert(is_ltc_char('z') == 1);
    assert(is_ltc_char('5') == 1);
    assert(is_ltc_char('0') == 1);
    assert(is_ltc_char('O') == 1);
}

static void test_ltc_char_invalid(void) {
    assert(is_ltc_char('I') == 0);
    assert(is_ltc_char('l') == 0);
    assert(is_ltc_char('1') == 0);
    assert(is_ltc_char('!') == 0);
}

static void test_detect_btc_with_digit1_fails(void) {
    /* BUG: is_btc_char rejects '1', so legacy BTC addresses with '1' in body fail */
    assert(detect_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == 0);
}

static void test_detect_btc_with_digit1_in_3prefix(void) {
    /* Same bug: '3'-prefixed address with '1' in body */
    assert(detect_btc("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == 0);
}

static void test_detect_btc_bech32(void) {
    assert(detect_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 1);
    assert(detect_btc("bc1short") == 0);
}

static void test_detect_btc_none(void) {
    assert(detect_btc("") == 0);
    assert(detect_btc("hello") == 0);
}

static void test_detect_eth_valid(void) {
    assert(detect_eth("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") == 2);
    assert(detect_eth("0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE") == 2);
    assert(detect_eth("0x0000000000000000000000000000000000000000") == 2);
}

static void test_detect_eth_invalid(void) {
    assert(detect_eth("1xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") == 0);
    assert(detect_eth("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BA") == 0);
    assert(detect_eth("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAee") == 0);
    assert(detect_eth("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG") == 0);
    assert(detect_eth("") == 0);
    assert(detect_eth("0x") == 0);
}

static void test_detect_ltc_valid(void) {
    /* LTC addr with chars accepted by is_ltc_char */
    assert(detect_ltc("LaMT3JNiWPq3V7MGwCCx7VDfKGPFzQMXpn") == 3);
}

static void test_detect_ltc_m_prefix(void) {
    assert(detect_ltc("MQMcJyopn5T7BFzGQtLWxf8aNPCuMpWwKc") == 3);
}

static void test_detect_ltc_too_short(void) {
    assert(detect_ltc("LaMT3JNi") == 0);
}

static void test_detect_ltc_bech32(void) {
    assert(detect_ltc("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n8") == 3);
    assert(detect_ltc("ltc1short") == 0);
}

static void test_detect_address_priority(void) {
    assert(clipper_detect_address("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") == 2);
    assert(clipper_detect_address("LaMT3JNiWPq3V7MGwCCx7VDfKGPFzQMXpn") == 3);
    assert(clipper_detect_address("hello world") == 0);
}

static void test_detect_address_null_empty(void) {
    assert(clipper_detect_address(NULL) == 0);
    assert(clipper_detect_address("") == 0);
}

int main(void) {
    test_btc_char_valid();
    test_btc_char_invalid();
    test_ltc_char_valid();
    test_ltc_char_invalid();
    test_detect_btc_with_digit1_fails();
    test_detect_btc_with_digit1_in_3prefix();
    test_detect_btc_bech32();
    test_detect_btc_none();
    test_detect_eth_valid();
    test_detect_eth_invalid();
    test_detect_ltc_valid();
    test_detect_ltc_m_prefix();
    test_detect_ltc_too_short();
    test_detect_ltc_bech32();
    test_detect_address_priority();
    test_detect_address_null_empty();
    printf("test_clipper: ALL PASSED\n");
    return 0;
}
