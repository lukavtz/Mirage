/*
 * test_asn1.c — ASN.1 DER reader tests (firefox_crypto.c pure functions)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  PASS: %s\n", name); tests_passed++; } while(0)
#define FAIL(name) do { tests_run++; printf("  FAIL: %s\n", name); } while(0)

/* ── FxAsn1Reader + functions (from firefox_crypto.c) ─────────── */

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} FxAsn1Reader;

static int fx_asn1_read_tag(FxAsn1Reader *r, uint8_t *tag) {
    if (r->pos >= r->len) return -1;
    *tag = r->data[r->pos++];
    return 0;
}

static int fx_asn1_read_length(FxAsn1Reader *r, size_t *length) {
    if (r->pos >= r->len) return -1;
    uint8_t first = r->data[r->pos++];
    if (!(first & 0x80)) { *length = first; return 0; }
    int n = first & 0x7F;
    if (n == 0 || n > 4) return -1;
    *length = 0;
    for (int i = 0; i < n; i++) {
        if (r->pos >= r->len) return -1;
        *length = (*length << 8) | r->data[r->pos++];
    }
    return 0;
}

static int fx_asn1_read_sequence(FxAsn1Reader *r, FxAsn1Reader *content) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x30) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    content->data = r->data + r->pos;
    content->len = len;
    content->pos = 0;
    r->pos += len;
    return 0;
}

static int fx_asn1_read_octet_string(FxAsn1Reader *r, const unsigned char **out, size_t *out_len) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x04) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    *out = r->data + r->pos;
    *out_len = len;
    r->pos += len;
    return 0;
}

static int fx_asn1_read_integer(FxAsn1Reader *r, uint64_t *value) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x02) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (len == 0 || len > 8 || r->pos + len > r->len) return -1;
    *value = 0;
    for (size_t i = 0; i < len; i++)
        *value = (*value << 8) | r->data[r->pos++];
    return 0;
}

static int fx_asn1_read_oid(FxAsn1Reader *r, const unsigned char **out, size_t *out_len) {
    uint8_t tag;
    if (fx_asn1_read_tag(r, &tag) < 0 || tag != 0x06) return -1;
    size_t len;
    if (fx_asn1_read_length(r, &len) < 0) return -1;
    if (r->pos + len > r->len) return -1;
    *out = r->data + r->pos;
    *out_len = len;
    r->pos += len;
    return 0;
}

static int fx_asn1_peek_tag(FxAsn1Reader *r, uint8_t *tag) {
    if (r->pos >= r->len) return -1;
    *tag = r->data[r->pos];
    return 0;
}

/* ── Tests ───────────────────────────────────────────────────── */

static void test_read_tag(void) {
    unsigned char data[] = {0x30, 0x04};
    FxAsn1Reader r = {data, 2, 0};
    uint8_t tag;
    if (fx_asn1_read_tag(&r, &tag) < 0 || tag != 0x30) { FAIL("test_read_tag"); return; }
    if (fx_asn1_read_tag(&r, &tag) < 0 || tag != 0x04) { FAIL("test_read_tag (2)"); return; }
    if (fx_asn1_read_tag(&r, &tag) != -1) { FAIL("test_read_tag (eof)"); return; }
    TEST("test_read_tag");
}

static void test_read_length_short(void) {
    unsigned char data[] = {0x7F}; /* 127 bytes, short form */
    FxAsn1Reader r = {data, 1, 0};
    size_t len;
    if (fx_asn1_read_length(&r, &len) < 0 || len != 127) { FAIL("test_read_length_short"); return; }
    TEST("test_read_length_short");
}

static void test_read_length_long(void) {
    unsigned char data[] = {0x82, 0x01, 0x00}; /* 256 bytes, long form */
    FxAsn1Reader r = {data, 3, 0};
    size_t len;
    if (fx_asn1_read_length(&r, &len) < 0 || len != 256) { FAIL("test_read_length_long"); return; }
    TEST("test_read_length_long");
}

static void test_read_sequence(void) {
    /* SEQUENCE { INTEGER 42 } */
    unsigned char data[] = {0x30, 0x03, 0x02, 0x01, 0x2A};
    FxAsn1Reader r = {data, 5, 0};
    FxAsn1Reader content;
    if (fx_asn1_read_sequence(&r, &content) < 0) { FAIL("test_read_sequence (parse)"); return; }
    uint64_t val;
    if (fx_asn1_read_integer(&content, &val) < 0 || val != 42) { FAIL("test_read_sequence (val)"); return; }
    TEST("test_read_sequence");
}

static void test_read_octet_string(void) {
    /* OCTET STRING { 0xDE, 0xAD } */
    unsigned char data[] = {0x04, 0x02, 0xDE, 0xAD};
    FxAsn1Reader r = {data, 4, 0};
    const unsigned char *out;
    size_t out_len;
    if (fx_asn1_read_octet_string(&r, &out, &out_len) < 0 || out_len != 2) { FAIL("test_read_octet_string"); return; }
    if (out[0] != 0xDE || out[1] != 0xAD) { FAIL("test_read_octet_string (val)"); return; }
    TEST("test_read_octet_string");
}

static void test_read_integer(void) {
    unsigned char data[] = {0x02, 0x01, 0xFF}; /* INTEGER 255 */
    FxAsn1Reader r = {data, 3, 0};
    uint64_t val;
    if (fx_asn1_read_integer(&r, &val) < 0 || val != 255) { FAIL("test_read_integer"); return; }
    TEST("test_read_integer");
}

static void test_read_integer_multi_byte(void) {
    unsigned char data[] = {0x02, 0x02, 0x01, 0x00}; /* INTEGER 256 */
    FxAsn1Reader r = {data, 4, 0};
    uint64_t val;
    if (fx_asn1_read_integer(&r, &val) < 0 || val != 256) { FAIL("test_read_integer_multi"); return; }
    TEST("test_read_integer_multi");
}

static void test_read_oid(void) {
    /* OID 1.2.840.113549 */
    unsigned char oid_bytes[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D};
    unsigned char data[8] = {0x06, 0x06};
    memcpy(data + 2, oid_bytes, 6);
    FxAsn1Reader r = {data, 8, 0};
    const unsigned char *out;
    size_t out_len;
    if (fx_asn1_read_oid(&r, &out, &out_len) < 0 || out_len != 6) { FAIL("test_read_oid"); return; }
    TEST("test_read_oid");
}

static void test_peek_tag(void) {
    unsigned char data[] = {0x30, 0x04};
    FxAsn1Reader r = {data, 2, 0};
    uint8_t tag;
    if (fx_asn1_peek_tag(&r, &tag) < 0 || tag != 0x30) { FAIL("test_peek_tag"); return; }
    if (r.pos != 0) { FAIL("test_peek_tag (pos)"); return; } /* peek doesn't advance */
    TEST("test_peek_tag");
}

static void test_truncated_input(void) {
    /* Empty buffer — read_length should fail */
    unsigned char data[] = {};
    FxAsn1Reader r = {data, 0, 0};
    size_t len;
    if (fx_asn1_read_length(&r, &len) != -1) { FAIL("test_truncated_input (empty)"); return; }
    /* Long-form with missing continuation bytes */
    unsigned char data2[] = {0x82}; /* needs 2 more bytes */
    FxAsn1Reader r2 = {data2, 1, 0};
    if (fx_asn1_read_length(&r2, &len) != -1) { FAIL("test_truncated_input (long)"); return; }
    TEST("test_truncated_input");
}

static void test_nested_sequence(void) {
    /* SEQUENCE { SEQUENCE { INTEGER 1 } } */
    unsigned char data[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01};
    FxAsn1Reader r = {data, 7, 0};
    FxAsn1Reader outer, inner;
    if (fx_asn1_read_sequence(&r, &outer) < 0) { FAIL("test_nested_seq (outer)"); return; }
    if (fx_asn1_read_sequence(&outer, &inner) < 0) { FAIL("test_nested_seq (inner)"); return; }
    uint64_t val;
    if (fx_asn1_read_integer(&inner, &val) < 0 || val != 1) { FAIL("test_nested_seq (val)"); return; }
    TEST("test_nested_sequence");
}

int main(void) {
    printf("=== test_asn1: ASN.1 DER reader ===\n");
    test_read_tag();
    test_read_length_short();
    test_read_length_long();
    test_read_sequence();
    test_read_octet_string();
    test_read_integer();
    test_read_integer_multi_byte();
    test_read_oid();
    test_peek_tag();
    test_truncated_input();
    test_nested_sequence();
    printf("=== test_asn1: %d/%d PASSED ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
