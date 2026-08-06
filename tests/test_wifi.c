/*
 * test_wifi.c — WiFi helper function tests (wide_to_narrow, xml_get_value)
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_wifi tests/test_wifi.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* ── Inline pure-logic helpers from wifi.c ────────────────── */

typedef unsigned short WCHAR;

static void wide_to_narrow(const WCHAR *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; i < dst_size - 1 && src[i]; i++)
        dst[i] = (src[i] < 0x80) ? (char)src[i] : '?';
    dst[i] = '\0';
}

static const char *xml_get_value(const char *xml, const char *tag, size_t *vlen) {
    size_t tlen = strlen(tag);
    char open[64], close[64];
    if (tlen + 3 >= sizeof(open)) return NULL;
    open[0] = '<'; memcpy(open + 1, tag, tlen); open[tlen + 1] = '>'; open[tlen + 2] = '\0';
    close[0] = '<'; close[1] = '/'; memcpy(close + 2, tag, tlen);
    close[tlen + 2] = '>'; close[tlen + 3] = '\0';
    const char *s = strstr(xml, open);
    if (!s) return NULL;
    s += tlen + 2;
    const char *e = strstr(s, close);
    if (!e) return NULL;
    *vlen = (size_t)(e - s);
    return s;
}

/* ── wide_to_narrow tests ────────────────────────────────── */

static void test_wide_ascii(void) {
    const WCHAR src[] = { 'H', 'e', 'l', 'l', 'o', 0 };
    char dst[32];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(strcmp(dst, "Hello") == 0);
}

static void test_wide_non_ascii(void) {
    const WCHAR src[] = { 'c', 'a', 'f', 0x00E9, 0 };
    char dst[32];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(strcmp(dst, "caf?") == 0);
}

static void test_wide_empty(void) {
    const WCHAR src[] = { 0 };
    char dst[32];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(strcmp(dst, "") == 0);
}

static void test_wide_truncate(void) {
    const WCHAR src[] = { 'A', 'B', 'C', 'D', 'E', 0 };
    char dst[4];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(strcmp(dst, "ABC") == 0);
}

static void test_wide_mixed(void) {
    const WCHAR src[] = { 'A', 0x0410, 'B', 0 };
    char dst[16];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(dst[0] == 'A');
    assert(dst[1] == '?');
    assert(dst[2] == 'B');
    assert(dst[3] == '\0');
}

static void test_wide_single_char(void) {
    const WCHAR src[] = { 'X', 0 };
    char dst[2];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(strcmp(dst, "X") == 0);
}

static void test_wide_size_one(void) {
    const WCHAR src[] = { 'A', 'B', 0 };
    char dst[1];
    wide_to_narrow(src, dst, sizeof(dst));
    assert(dst[0] == '\0');
}

/* ── xml_get_value tests ─────────────────────────────────── */

static void test_xml_simple(void) {
    const char *xml = "<keyMaterial>password123</keyMaterial>";
    size_t vlen;
    const char *val = xml_get_value(xml, "keyMaterial", &vlen);
    assert(val != NULL);
    assert(vlen == 11);
    assert(memcmp(val, "password123", 11) == 0);
}

static void test_xml_not_found(void) {
    const char *xml = "<other>data</other>";
    size_t vlen;
    const char *val = xml_get_value(xml, "keyMaterial", &vlen);
    assert(val == NULL);
}

static void test_xml_empty_value(void) {
    const char *xml = "<keyMaterial></keyMaterial>";
    size_t vlen;
    const char *val = xml_get_value(xml, "keyMaterial", &vlen);
    assert(val != NULL);
    assert(vlen == 0);
}

static void test_xml_nested_context(void) {
    const char *xml =
        "<WLANProfile>"
        "<name>MyNetwork</name>"
        "<MSM><security><sharedKey>"
        "<keyMaterial>MySecretPass</keyMaterial>"
        "</sharedKey></security></MSM>"
        "</WLANProfile>";
    size_t vlen;
    const char *val = xml_get_value(xml, "keyMaterial", &vlen);
    assert(val != NULL);
    assert(vlen == 12);
    assert(memcmp(val, "MySecretPass", 12) == 0);
}

static void test_xml_multiple_tags(void) {
    const char *xml = "<name>SSID1</name><keyMaterial>pass123</keyMaterial>";
    size_t vlen;
    const char *name = xml_get_value(xml, "name", &vlen);
    assert(name != NULL);
    assert(vlen == 5);

    const char *key = xml_get_value(xml, "keyMaterial", &vlen);
    assert(key != NULL);
    assert(vlen == 7);
}

static void test_xml_no_close_tag(void) {
    const char *xml = "<keyMaterial>password123";
    size_t vlen;
    const char *val = xml_get_value(xml, "keyMaterial", &vlen);
    assert(val == NULL);
}

static void test_xml_tag_too_long(void) {
    char long_tag[70];
    memset(long_tag, 'a', 65);
    long_tag[65] = '\0';
    char xml[200];
    snprintf(xml, sizeof(xml), "<%s>data</%s>", long_tag, long_tag);
    size_t vlen;
    const char *val = xml_get_value(xml, long_tag, &vlen);
    assert(val == NULL);
}

int main(void) {
    test_wide_ascii();
    test_wide_non_ascii();
    test_wide_empty();
    test_wide_truncate();
    test_wide_mixed();
    test_wide_single_char();
    test_wide_size_one();
    test_xml_simple();
    test_xml_not_found();
    test_xml_empty_value();
    test_xml_nested_context();
    test_xml_multiple_tags();
    test_xml_no_close_tag();
    test_xml_tag_too_long();
    printf("test_wifi: ALL PASSED\n");
    return 0;
}
