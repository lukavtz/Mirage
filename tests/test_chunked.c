/*
 * test_chunked.c — Chunked multipart body builder tests
 *
 * Tests: chunked_build_chunk_body, chunked_build_complete_body,
 *        chunked_generate_session_id — multipart format validation.
 *
 * Build (Windows with mock seam):
 *   gcc -Wall -Wextra -O2 -Wno-error -Iinclude -Isrc -Isrc/network
 *       -Isrc/types -Isrc/utils -Isrc/parsers -std=c11 -DZIALFI_TEST_MODE
 *       -o tests/test_chunked.exe tests/test_chunked.c src/network/chunked.c
 *       src/network/ws2.c src/network/ws2_peb.c src/types/hash.c
 *       src/types/export_resolve.c src/types/peb.c -lws2_32 -ladvapi32
 *
 * Build (Linux):
 *   gcc -Wall -Wextra -O2 -Iinclude -Isrc -Isrc/network -std=c11
 *       -o tests/test_chunked tests/test_chunked.c src/network/chunked.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "chunked.h"

#ifdef _WIN32
void *getPeb(void) { return NULL; }
#endif

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

static const unsigned char *find_in_buf(const unsigned char *hay, size_t hlen,
                                         const unsigned char *needle, size_t nlen) {
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    return NULL;
}

static int count_occurrences(const uint8_t *buf, size_t blen,
                              const char *needle, size_t nlen) {
    int count = 0;
    for (size_t i = 0; i + nlen <= blen; i++) {
        if (memcmp(buf + i, needle, nlen) == 0) count++;
    }
    return count;
}

/* ── chunked_build_chunk_body tests ──────────────────────────── */

static void test_build_chunk_body_basic(void) {
    const char *boundary = "----MyBoundary";
    const char *session = "abc123";
    const uint8_t data[] = "Hello, World!";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0,
                                              data, sizeof(data) - 1, &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    assert(find_in_buf(body, out_len, (const uint8_t*)boundary, strlen(boundary)));
    assert(find_in_buf(body, out_len, (const uint8_t*)session, strlen(session)));
    assert(find_in_buf(body, out_len, data, sizeof(data) - 1));
    free(body);
    TEST("test_build_chunk_body_basic");
}

static void test_build_chunk_body_different_index(void) {
    const char *boundary = "----B";
    const char *session = "s1";
    const uint8_t data[] = "X";
    size_t out_len = 0;

    uint8_t *body0 = chunked_build_chunk_body(boundary, session, 0, data, 1, &out_len);
    assert(body0 != NULL);
    assert(find_in_buf(body0, out_len, (const uint8_t*)"0", 1));
    free(body0);

    uint8_t *body99 = chunked_build_chunk_body(boundary, session, 99, data, 1, &out_len);
    assert(body99 != NULL);
    assert(find_in_buf(body99, out_len, (const uint8_t*)"99", 2));
    free(body99);

    uint8_t *body1000 = chunked_build_chunk_body(boundary, session, 1000, data, 1, &out_len);
    assert(body1000 != NULL);
    assert(find_in_buf(body1000, out_len, (const uint8_t*)"1000", 4));
    free(body1000);

    TEST("test_build_chunk_body_different_index");
}

static void test_build_chunk_body_session_id_present(void) {
    const char *boundary = "----BOUND";
    const char *session = "0123456789abcdef0123456789abcdef";
    const uint8_t data[] = "data";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 5, data, 4, &out_len);
    assert(body != NULL);
    assert(find_in_buf(body, out_len, (const uint8_t*)"name=\"session_id\"", 17));
    assert(find_in_buf(body, out_len, (const uint8_t*)session, 32));
    free(body);
    TEST("test_build_chunk_body_session_id_present");
}

static void test_build_chunk_body_content_disposition(void) {
    const char *boundary = "----B";
    const char *session = "s";
    const uint8_t data[] = "d";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, data, 1, &out_len);
    assert(body != NULL);
    assert(find_in_buf(body, out_len, (const uint8_t*)"filename=\"chunk.bin\"", 20));
    assert(find_in_buf(body, out_len, (const uint8_t*)"Content-Type: application/octet-stream", 38));
    free(body);
    TEST("test_build_chunk_body_content_disposition");
}

static void test_build_chunk_body_zero_data(void) {
    const char *boundary = "----B";
    const char *session = "s";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, (const uint8_t*)"", 0, &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    assert(find_in_buf(body, out_len, (const uint8_t*)"--B--\r\n", 7));
    free(body);
    TEST("test_build_chunk_body_zero_data");
}

static void test_build_chunk_body_large_data(void) {
    const char *boundary = "----B";
    const char *session = "s";
    size_t data_len = 65536;
    uint8_t *data = malloc(data_len);
    assert(data != NULL);
    memset(data, 'Z', data_len);
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, data, data_len, &out_len);
    assert(body != NULL);
    assert(out_len > data_len);
    assert(find_in_buf(body, out_len, data, data_len));
    free(data);
    free(body);
    TEST("test_build_chunk_body_large_data");
}

/* ── chunked_build_complete_body tests ───────────────────────── */

static void test_build_complete_body(void) {
    const char *boundary = "----CompleteBnd";
    const char *session = "sess123";
    const char *meta = "{\"key\":\"value\"}";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 42,
                                                 meta, strlen(meta), &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    assert(find_in_buf(body, out_len, (const uint8_t*)session, strlen(session)));
    assert(find_in_buf(body, out_len, (const uint8_t*)"42", 2));
    assert(find_in_buf(body, out_len, (const uint8_t*)meta, strlen(meta)));
    free(body);
    TEST("test_build_complete_body");
}

static void test_build_complete_body_null_metadata(void) {
    const char *boundary = "----B";
    const char *session = "s";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 1, NULL, 0, &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    assert(find_in_buf(body, out_len, (const uint8_t*)"--B--\r\n", 7));
    free(body);
    TEST("test_build_complete_body_null_metadata");
}

static void test_build_complete_body_fields(void) {
    const char *boundary = "----B";
    const char *session = "s";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 10,
                                                 "meta", 4, &out_len);
    assert(body != NULL);
    assert(find_in_buf(body, out_len, (const uint8_t*)"name=\"total_chunks\"", 19));
    assert(find_in_buf(body, out_len, (const uint8_t*)"name=\"metadata\"", 15));
    assert(find_in_buf(body, out_len, (const uint8_t*)"name=\"session_id\"", 17));
    free(body);
    TEST("test_build_complete_body_fields");
}

/* ── session id tests (may fail if crypto API unavailable) ──── */

static void test_session_id_generation(void) {
    char *id1 = chunked_generate_session_id();
    char *id2 = chunked_generate_session_id();
    if (!id1 || !id2) {
        printf("  SKIP: test_session_id_generation (crypto API unavailable in test mode)\n");
        free(id1); free(id2);
        return;
    }
    assert(strlen(id1) == 32);
    assert(strlen(id2) == 32);
    assert(strcmp(id1, id2) != 0);
    for (int i = 0; i < 32; i++) {
        char c = id1[i];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    free(id1);
    free(id2);
    TEST("test_session_id_generation");
}

static void test_session_id_hex_format(void) {
    char *id = chunked_generate_session_id();
    if (!id) {
        printf("  SKIP: test_session_id_hex_format (crypto API unavailable in test mode)\n");
        return;
    }
    assert(strlen(id) == 32);
    assert(id[32] == '\0');
    free(id);
    TEST("test_session_id_hex_format");
}

/* ── closing boundary tests ──────────────────────────────────── */

static void test_chunk_body_closing_boundary(void) {
    const char *boundary = "----XYZ";
    const char *session = "s";
    const uint8_t data[] = "data";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, data, 4, &out_len);
    assert(body != NULL);
    const char *closing = "--XYZ--\r\n";
    size_t clen = strlen(closing);
    assert(out_len >= clen);
    assert(memcmp(body + out_len - clen, closing, clen) == 0);
    free(body);
    TEST("test_chunk_body_closing_boundary");
}

static void test_complete_body_closing_boundary(void) {
    const char *boundary = "----ABC";
    const char *session = "s";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 1, "m", 1, &out_len);
    assert(body != NULL);
    const char *closing = "--ABC--\r\n";
    size_t clen = strlen(closing);
    assert(out_len >= clen);
    assert(memcmp(body + out_len - clen, closing, clen) == 0);
    free(body);
    TEST("test_complete_body_closing_boundary");
}

/* ── multipart structure tests ───────────────────────────────── */

static void test_boundary_occurrences_chunk(void) {
    const char *boundary = "----BND";
    const char *session = "s";
    const uint8_t data[] = "d";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, data, 1, &out_len);
    assert(body != NULL);
    int cnt = count_occurrences(body, out_len, "--BND", 5);
    assert(cnt == 4);
    free(body);
    TEST("test_boundary_occurrences_chunk");
}

static void test_boundary_occurrences_complete(void) {
    const char *boundary = "----BND";
    const char *session = "s";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 1, "m", 1, &out_len);
    assert(body != NULL);
    int cnt = count_occurrences(body, out_len, "--BND", 5);
    assert(cnt == 4);
    free(body);
    TEST("test_boundary_occurrences_complete");
}

static void test_crlf_separators(void) {
    const char *boundary = "----B";
    const char *session = "s";
    const uint8_t data[] = "d";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body(boundary, session, 0, data, 1, &out_len);
    assert(body != NULL);
    assert(find_in_buf(body, out_len, (const uint8_t*)"\r\n", 2));
    free(body);
    TEST("test_crlf_separators");
}

/* ── main ────────────────────────────────────────────────────── */

int main(void) {
    printf("=== test_chunked: Chunked multipart tests ===\n");

    test_build_chunk_body_basic();
    test_build_chunk_body_different_index();
    test_build_chunk_body_session_id_present();
    test_build_chunk_body_content_disposition();
    test_build_chunk_body_zero_data();
    test_build_chunk_body_large_data();
    test_build_complete_body();
    test_build_complete_body_null_metadata();
    test_build_complete_body_fields();
    test_session_id_generation();
    test_session_id_hex_format();
    test_chunk_body_closing_boundary();
    test_complete_body_closing_boundary();
    test_boundary_occurrences_chunk();
    test_boundary_occurrences_complete();
    test_crlf_separators();

    printf("=== test_chunked: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
