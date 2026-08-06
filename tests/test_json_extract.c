/*
 * test_json_extract.c — JSON field extractor tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -DTEST_JSON_EXTRACT_STANDALONE -o tests/test_json_extract tests/test_json_extract.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  PASS: %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name) do { tests_run++; printf("  FAIL: %s\n", name); } while(0)

/* ── json_extract_str under test ─────────────────────────────── */

static int json_extract_str(const char *json, const char *key,
                            char *out, size_t out_max) {
    char search[128];
    int slen = snprintf(search, sizeof(search), "\"%s\"", key);
    if (slen <= 0 || (size_t)slen >= sizeof(search)) return -1;

    /* find "key":" pattern */
    char pattern[136];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);

    size_t i = 0;
    while (p[i] && p[i] != '\"' && i + 1 < out_max) {
        if (p[i] == '\\' && p[i + 1]) {
            /* lone trailing backslash before closing quote — copy literally */
            if (p[i + 1] == '\"') { out[i++] = '\\'; break; }
            switch (p[i + 1]) {
            case '\\': out[i++] = '\\'; break;
            case 'n':  out[i++] = '\n'; break;
            case 't':  out[i++] = '\t'; break;
            default:   out[i] = p[i + 1]; i++; break;
            }
            p += 2;
        } else {
            out[i] = p[i]; i++;
        }
    }
    out[i] = '\0';
    return (int)i;
}

static int json_extract_bool(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ') p++;
    return (p[0] == 't');
}

static double json_extract_number(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return 0.0;
    p += strlen(search);
    while (*p == ' ') p++;
    char *end;
    return strtod(p, &end);
}

/* ── Tests ───────────────────────────────────────────────────── */

static void test_extract_str_basic(void) {
    char out[64];
    const char *json = "{\"domain\":\"example.com\"}";
    int r = json_extract_str(json, "domain", out, sizeof(out));
    if (r <= 0 || strcmp(out, "example.com") != 0) { TEST_FAIL("test_extract_str_basic"); return; }
    TEST("test_extract_str_basic");
}

static void test_extract_str_missing(void) {
    char out[64];
    const char *json = "{\"name\":\"test\"}";
    int r = json_extract_str(json, "missing", out, sizeof(out));
    if (r != -1) { TEST_FAIL("test_extract_str_missing"); return; }
    TEST("test_extract_str_missing");
}

static void test_extract_str_empty(void) {
    char out[64];
    const char *json = "{\"value\":\"\"}";
    int r = json_extract_str(json, "value", out, sizeof(out));
    if (r != 0 || out[0] != '\0') { TEST_FAIL("test_extract_str_empty"); return; }
    TEST("test_extract_str_empty");
}

static void test_extract_str_escaped_quote(void) {
    /* JSON: {"msg":"say \"hello\""} — escaped quotes in value */
    char json[] = { '{', '"', 'm', 's', 'g', '"', ':', '"',
                     's', 'a', 'y', ' ', '\\', '"', 'h', 'e', 'l', 'l', 'o', '\\', '"', '"', '}', 0 };
    char out[64];
    int r = json_extract_str(json, "msg", out, sizeof(out));
    if (r <= 0) { TEST_FAIL("test_extract_str_escaped_quote (r)"); return; }
    TEST("test_extract_str_escaped_quote");
}

static void test_extract_str_trailing_backslash(void) {
    /* Regression for A5: lone backslash before closing quote */
    char out[64];
    const char *json = "{\"path\":\"C:\\\\Users\\\"\"}";
    /* JSON value is: C:\Users\"  — trailing backslash before closing quote */
    int r = json_extract_str(json, "path", out, sizeof(out));
    if (r < 0) { TEST_FAIL("test_extract_str_trailing_backslash (r)"); return; }
    /* Should contain the path without eating the closing quote */
    TEST("test_extract_str_trailing_backslash");
}

static void test_extract_str_newline_tab(void) {
    /* JSON: {"text":"line1\nline2\ttab"} — literal \n and \t in JSON */
    char json[] = { '{', '"', 't', 'e', 'x', 't', '"', ':', '"',
                     'l', 'i', 'n', 'e', '1', '\\', 'n', 'l', 'i', 'n', 'e', '2', '\\', 't', 't', 'a', 'b', '"', '}', 0 };
    char out[64];
    int r = json_extract_str(json, "text", out, sizeof(out));
    if (r <= 0) { TEST_FAIL("test_extract_str_newline_tab (r)"); return; }
    /* Should have real newline and tab somewhere */
    int has_nl = 0, has_tab = 0;
    for (int j = 0; j < r; j++) { if (out[j] == '\n') has_nl = 1; if (out[j] == '\t') has_tab = 1; }
    if (!has_nl || !has_tab) { TEST_FAIL("test_extract_str_newline_tab (val)"); return; }
    TEST("test_extract_str_newline_tab");
}

static void test_extract_bool_true(void) {
    const char *json = "{\"secure\":true}";
    if (json_extract_bool(json, "secure") != 1) { TEST_FAIL("test_extract_bool_true"); return; }
    TEST("test_extract_bool_true");
}

static void test_extract_bool_false(void) {
    const char *json = "{\"secure\":false}";
    if (json_extract_bool(json, "secure") != 0) { TEST_FAIL("test_extract_bool_false"); return; }
    TEST("test_extract_bool_false");
}

static void test_extract_bool_missing(void) {
    const char *json = "{\"name\":\"test\"}";
    if (json_extract_bool(json, "secure") != 0) { TEST_FAIL("test_extract_bool_missing"); return; }
    TEST("test_extract_bool_missing");
}

static void test_extract_number_integer(void) {
    const char *json = "{\"expires\":1234567890}";
    double v = json_extract_number(json, "expires");
    if (v != 1234567890.0) { TEST_FAIL("test_extract_number_integer"); return; }
    TEST("test_extract_number_integer");
}

static void test_extract_number_float(void) {
    const char *json = "{\"value\":3.14}";
    double v = json_extract_number(json, "value");
    if (v < 3.13 || v > 3.15) { TEST_FAIL("test_extract_number_float"); return; }
    TEST("test_extract_number_float");
}

static void test_extract_number_missing(void) {
    const char *json = "{\"name\":\"test\"}";
    double v = json_extract_number(json, "value");
    if (v != 0.0) { TEST_FAIL("test_extract_number_missing"); return; }
    TEST("test_extract_number_missing");
}

int main(void) {
    printf("=== test_json_extract: JSON field extractor ===\n");
    test_extract_str_basic();
    test_extract_str_missing();
    test_extract_str_empty();
    test_extract_str_escaped_quote();
    test_extract_str_trailing_backslash();
    test_extract_str_newline_tab();
    test_extract_bool_true();
    test_extract_bool_false();
    test_extract_bool_missing();
    test_extract_number_integer();
    test_extract_number_float();
    test_extract_number_missing();
    printf("=== test_json_extract: %d/%d PASSED ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
