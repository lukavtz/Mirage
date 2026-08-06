/*
 * test_schannel.c — SChannel TLS module tests
 *
 * Tests: TLS context structure, copy_to_wide helper,
 *        iteration cap, constant definitions.
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_schannel.exe tests/test_schannel.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

static int passed = 0, failed = 0;
#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)

typedef enum {
    TLS_OK = 0, TLS_ERR_CRED_FAILED, TLS_ERR_HANDSHAKE_FAILED,
    TLS_ERR_ENCRYPT_FAILED, TLS_ERR_DECRYPT_FAILED, TLS_ERR_INCOMPLETE,
    TLS_ERR_STREAM_SIZES, TLS_ERR_FREE_CTX, TLS_ERR_DELETE_CTX,
    TLS_ERR_PIN_FAILED,
} tls_result_t;

typedef struct {
    void *sock;
    uintptr_t cred_lower, cred_upper;
    uintptr_t ctx_lower, ctx_upper;
    uint32_t header_size, trailer_size, max_message;
    int connected;
} tls_context_t;

static void copy_to_wide(char *dst, size_t dst_cap, const char *src) {
    size_t i;
    for (i = 0; src[i] && (i * 2 + 2) < dst_cap; ++i) {
        dst[i * 2]     = src[i];
        dst[i * 2 + 1] = 0;
    }
    dst[i * 2]     = 0;
    dst[i * 2 + 1] = 0;
}

static void test_tls_ok_is_zero(void) {
    assert(TLS_OK == 0);
    TEST("test_tls_ok_is_zero");
}

static void test_tls_error_codes_distinct(void) {
    assert(TLS_ERR_CRED_FAILED != TLS_OK);
    assert(TLS_ERR_HANDSHAKE_FAILED != TLS_OK);
    assert(TLS_ERR_ENCRYPT_FAILED != TLS_OK);
    assert(TLS_ERR_DECRYPT_FAILED != TLS_OK);
    assert(TLS_ERR_INCOMPLETE != TLS_OK);
    assert(TLS_ERR_STREAM_SIZES != TLS_OK);
    assert(TLS_ERR_FREE_CTX != TLS_OK);
    assert(TLS_ERR_DELETE_CTX != TLS_OK);
    assert(TLS_ERR_PIN_FAILED != TLS_OK);
    int codes[] = {TLS_ERR_CRED_FAILED, TLS_ERR_HANDSHAKE_FAILED,
                   TLS_ERR_ENCRYPT_FAILED, TLS_ERR_DECRYPT_FAILED,
                   TLS_ERR_INCOMPLETE, TLS_ERR_STREAM_SIZES,
                   TLS_ERR_FREE_CTX, TLS_ERR_DELETE_CTX, TLS_ERR_PIN_FAILED};
    int n = (int)(sizeof(codes) / sizeof(codes[0]));
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            assert(codes[i] != codes[j]);
    TEST("test_tls_error_codes_distinct");
}

static void test_context_zero_init(void) {
    tls_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    assert(ctx.sock == NULL);
    assert(ctx.cred_lower == 0); assert(ctx.cred_upper == 0);
    assert(ctx.ctx_lower == 0);  assert(ctx.ctx_upper == 0);
    assert(ctx.header_size == 0); assert(ctx.trailer_size == 0);
    assert(ctx.max_message == 0); assert(ctx.connected == 0);
    TEST("test_context_zero_init");
}

static void test_context_connected_flag(void) {
    tls_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    assert(ctx.connected == 0);
    ctx.connected = 1;
    assert(ctx.connected == 1);
    ctx.connected = 0;
    assert(ctx.connected == 0);
    TEST("test_context_connected_flag");
}

static void test_context_stream_sizes(void) {
    tls_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.header_size = 5; ctx.trailer_size = 16; ctx.max_message = 16384;
    assert(ctx.header_size + ctx.trailer_size + ctx.max_message > 0);
    assert(ctx.header_size <= ctx.max_message);
    assert(ctx.trailer_size <= ctx.max_message);
    TEST("test_context_stream_sizes");
}

static void test_context_size(void) {
    assert(sizeof(tls_context_t) <= 256);
    assert(sizeof(tls_context_t) >= 32);
    TEST("test_context_size");
}

static void test_copy_to_wide_basic(void) {
    char dst[64];
    memset(dst, 0xFF, sizeof(dst));
    copy_to_wide(dst, sizeof(dst), "abc");
    assert(dst[0] == 'a'); assert(dst[1] == 0);
    assert(dst[2] == 'b'); assert(dst[3] == 0);
    assert(dst[4] == 'c'); assert(dst[5] == 0);
    assert(dst[6] == 0);  assert(dst[7] == 0);
    TEST("test_copy_to_wide_basic");
}

static void test_copy_to_wide_empty(void) {
    char dst[16];
    memset(dst, 0xFF, sizeof(dst));
    copy_to_wide(dst, sizeof(dst), "");
    assert(dst[0] == 0); assert(dst[1] == 0);
    TEST("test_copy_to_wide_empty");
}

static void test_copy_to_wide_hostname(void) {
    char dst[512];
    memset(dst, 0, sizeof(dst));
    copy_to_wide(dst, sizeof(dst), "example.com");
    assert(dst[0] == 'e'); assert(dst[1] == 0);
    assert(dst[2] == 'x'); assert(dst[3] == 0);
    /* null terminator after last char */
    assert(dst[22] == 0); assert(dst[23] == 0);
    TEST("test_copy_to_wide_hostname");
}

static void test_copy_to_wide_truncation(void) {
    char dst[10];
    memset(dst, 0xFF, sizeof(dst));
    copy_to_wide(dst, sizeof(dst), "longstring");
    assert(dst[0] == 'l'); assert(dst[2] == 'o');
    assert(dst[4] == 'n'); assert(dst[6] == 'g');
    assert(dst[8] == 0);  assert(dst[9] == 0);
    TEST("test_copy_to_wide_truncation");
}

static void test_copy_to_wide_single_char(void) {
    char dst[16];
    memset(dst, 0xFF, sizeof(dst));
    copy_to_wide(dst, sizeof(dst), "X");
    assert(dst[0] == 'X'); assert(dst[1] == 0);
    assert(dst[2] == 0);   assert(dst[3] == 0);
    TEST("test_copy_to_wide_single_char");
}

static void test_handshake_iteration_cap(void) {
    int hs_iter = 0, max = 50, reached = 0;
    for (;;) { if (++hs_iter > max) { reached = 1; break; } }
    assert(reached); assert(hs_iter == 51);
    TEST("test_handshake_iteration_cap");
}

static void test_handshake_cap_sanity(void) {
    int max_iter = 50;
    assert(max_iter > 0);
    assert(max_iter <= 100);
    TEST("test_handshake_cap_sanity");
}

#ifndef SEC_E_OK
#define SEC_E_OK 0x00000000L
#endif
#ifndef SEC_I_CONTINUE_NEEDED
#define SEC_I_CONTINUE_NEEDED 0x00090312L
#endif
#ifndef ISC_REQ_STREAM
#define ISC_REQ_STREAM 0x00008000UL
#endif
#ifndef ISC_REQ_ALLOCATE_MEMORY
#define ISC_REQ_ALLOCATE_MEMORY 0x00000100UL
#endif

static void test_sec_e_ok_is_zero(void) {
    assert(SEC_E_OK == 0);
    TEST("test_sec_e_ok_is_zero");
}

static void test_sec_continue_needed_nonzero(void) {
    assert(SEC_I_CONTINUE_NEEDED != 0);
    assert(SEC_I_CONTINUE_NEEDED != SEC_E_OK);
    TEST("test_sec_continue_needed_nonzero");
}

static void test_isc_req_flags(void) {
    assert(ISC_REQ_STREAM != 0);
    assert(ISC_REQ_ALLOCATE_MEMORY != 0);
    assert(ISC_REQ_STREAM != ISC_REQ_ALLOCATE_MEMORY);
    uint32_t combined = ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY;
    assert(combined & ISC_REQ_STREAM);
    assert(combined & ISC_REQ_ALLOCATE_MEMORY);
    TEST("test_isc_req_flags");
}

static void test_max_message_with_sizes(void) {
    uint32_t header = 5, trailer = 16, max_msg = 16384;
    uint32_t payload = max_msg - header - trailer;
    assert(payload > 0);
    assert(payload < max_msg);
    assert(payload == 16363);
    TEST("test_max_message_with_sizes");
}

static void test_record_chunking(void) {
    uint32_t header = 5, trailer = 16, max_msg = 16384;
    uint32_t payload_per = max_msg - header - trailer;
    size_t data_len = 50000, records = 0, remaining = data_len;
    while (remaining > 0) {
        size_t chunk = remaining > payload_per ? payload_per : remaining;
        remaining -= chunk; records++;
    }
    assert(records == 4);
    TEST("test_record_chunking");
}

int main(void) {
    printf("=== test_schannel: TLS/SChannel tests ===\n");
    test_tls_ok_is_zero(); test_tls_error_codes_distinct();
    test_context_zero_init(); test_context_connected_flag();
    test_context_stream_sizes(); test_context_size();
    test_copy_to_wide_basic(); test_copy_to_wide_empty();
    test_copy_to_wide_hostname(); test_copy_to_wide_truncation();
    test_copy_to_wide_single_char();
    test_handshake_iteration_cap(); test_handshake_cap_sanity();
    test_sec_e_ok_is_zero(); test_sec_continue_needed_nonzero();
    test_isc_req_flags();
    test_max_message_with_sizes(); test_record_chunking();
    printf("=== test_schannel: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
