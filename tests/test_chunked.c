/*
 * test_chunked.c — Chunked multipart body builder tests
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_chunked.exe tests/test_chunked.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "chunked.h"

/* memmem not available on Windows; inline helper */
static const unsigned char *find_in_buf(const unsigned char *hay, size_t hlen,
                                         const unsigned char *needle, size_t nlen) {
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    return NULL;
}

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
    printf("  PASS: test_build_chunk_body_basic\n");
}

static void test_build_chunk_body_different_index(void) {
    const char *boundary = "----B";
    const uint8_t data[] = "X";
    size_t len1 = 0, len2 = 0;
    uint8_t *b1 = chunked_build_chunk_body(boundary, "s", 0, data, 1, &len1);
    uint8_t *b2 = chunked_build_chunk_body(boundary, "s", 5, data, 1, &len2);
    assert(b1 && b2);
    assert(find_in_buf(b1, len1, (const uint8_t*)"0", 1));
    assert(find_in_buf(b2, len2, (const uint8_t*)"5", 1));
    free(b1); free(b2);
    printf("  PASS: test_build_chunk_body_different_index\n");
}

static void test_build_complete_body(void) {
    const char *boundary = "----Complete";
    const char *session = "sess456";
    const char *metadata = "{\"host\":\"test\"}";
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body(boundary, session, 10,
                                                  metadata, strlen(metadata), &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    assert(find_in_buf(body, out_len, (const uint8_t*)session, strlen(session)));
    assert(find_in_buf(body, out_len, (const uint8_t*)metadata, strlen(metadata)));
    assert(find_in_buf(body, out_len, (const uint8_t*)"10", 2));
    free(body);
    printf("  PASS: test_build_complete_body\n");
}

static void test_build_complete_body_null_metadata(void) {
    size_t out_len = 0;
    uint8_t *body = chunked_build_complete_body("----B", "s", 1, NULL, 0, &out_len);
    assert(body != NULL);
    assert(out_len > 0);
    free(body);
    printf("  PASS: test_build_complete_body_null_metadata\n");
}

static void test_session_id_generation(void) {
    char *id1 = chunked_generate_session_id();
    char *id2 = chunked_generate_session_id();
    assert(id1 && id2);
    assert(strlen(id1) == 32);
    assert(strlen(id2) == 32);
    assert(strcmp(id1, id2) != 0);
    for (int i = 0; i < 32; i++) {
        char c = id1[i];
        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    free(id1); free(id2);
    printf("  PASS: test_session_id_generation\n");
}

static void test_chunk_body_closing_boundary(void) {
    const uint8_t data[] = "D";
    size_t out_len = 0;
    uint8_t *body = chunked_build_chunk_body("----END", "s", 0, data, 1, &out_len);
    assert(body != NULL);
    assert(body[out_len - 1] == '\n');
    assert(body[out_len - 2] == '\r');
    assert(body[out_len - 3] == '-');
    assert(body[out_len - 4] == '-');
    free(body);
    printf("  PASS: test_chunk_body_closing_boundary\n");
}

int main(void) {
    printf("=== test_chunked: multipart body builders ===\n");
    test_build_chunk_body_basic();
    test_build_chunk_body_different_index();
    test_build_complete_body();
    test_build_complete_body_null_metadata();
    test_session_id_generation();
    test_chunk_body_closing_boundary();
    printf("=== test_chunked: ALL PASSED ===\n");
    return 0;
}
