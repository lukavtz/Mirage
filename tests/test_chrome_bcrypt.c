/*
 * test_chrome_bcrypt.c — RED test for the REAL BCrypt path in chrome_crypto.c
 *
 * Links src/crypto/chrome_crypto.c directly (Windows/BCrypt path is active
 * under mingw since _WIN32 is defined) and installs a mock bcrypt API via
 * mirage_bcrypt_api_install() so no real bcrypt.dll or PEB walk is needed.
 *
 * The mock pDecrypt returns STATUS_AUTH_TAG_MISMATCH (0xC000A002-ish failure)
 * for a corrupted-tag blob — chrome_decrypt_password MUST propagate that as
 * -1 with *out_len == 0. Current code ignores the NTSTATUS and returns 0.
 *
 * Build: gcc -DTEST_CHROME_BCRYPT ... -lbcrypt (see Makefile test-chrome-bcrypt)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define TEST_CHROME_BCRYPT
#include <windows.h>
#include <bcrypt.h>

#include "bcrypt_peb.h"
#include "chrome_crypto.h"

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name) do { printf("  FAIL: %s\n", name); failed++; } while(0)

static int passed = 0, failed = 0;

/* Stub for the NASM getPeb symbol referenced by peb.c */
void *getPeb(void) { return NULL; }

/* STATUS_AUTH_TAG_MISMATCH */
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)

/* ── Mock BCrypt implementations ─────────────────────────── */

static NTSTATUS WINAPI mock_open(BCRYPT_ALG_HANDLE *h, LPCWSTR a, LPCWSTR b, ULONG c) {
    (void)a;(void)b;(void)c; *h = (BCRYPT_ALG_HANDLE)0x1234; return 0;
}
static NTSTATUS WINAPI mock_close(BCRYPT_ALG_HANDLE h, ULONG f) { (void)h;(void)f; return 0; }
static NTSTATUS WINAPI mock_setprop(BCRYPT_ALG_HANDLE h, LPCWSTR p, PUCHAR v, ULONG l, ULONG f) {
    (void)h;(void)p;(void)v;(void)l;(void)f; return 0;
}
static NTSTATUS WINAPI mock_genkey(BCRYPT_ALG_HANDLE h, BCRYPT_KEY_HANDLE *k, PUCHAR b, ULONG bl,
                                    PUCHAR key, ULONG kl, ULONG f) {
    (void)h;(void)b;(void)bl;(void)key;(void)kl;(void)f; *k = (BCRYPT_KEY_HANDLE)0x5678; return 0;
}
static NTSTATUS WINAPI mock_derive(BCRYPT_ALG_HANDLE h, PUCHAR p, ULONG pl, PUCHAR s, ULONG sl,
                                   ULONGLONG it, PUCHAR o, ULONG ol, ULONG f) {
    (void)h;(void)p;(void)pl;(void)s;(void)sl;(void)it;(void)ol;(void)f;
    memset(o, 0x00, ol);
    return 0;
}

/* g_fail_decrypt forces pDecrypt to return STATUS_AUTH_TAG_MISMATCH */
static int g_fail_decrypt = 0;
static int g_decrypt_calls = 0;

static NTSTATUS WINAPI mock_decrypt(BCRYPT_KEY_HANDLE h, PUCHAR ct, ULONG ctl, PVOID info,
                                    PUCHAR iv, ULONG ivl, PUCHAR out, ULONG outl,
                                    ULONG *result_len, ULONG f) {
    (void)h;(void)ct;(void)ctl;(void)iv;(void)ivl;(void)out;(void)outl;(void)f;
    g_decrypt_calls++;
    if (g_fail_decrypt) {
        if (result_len) *result_len = 0;
        return STATUS_AUTH_TAG_MISMATCH;
    }
    /* Deterministic "plaintext" = byte-inverted ciphertext */
    for (ULONG i = 0; i < ctl && i < outl; i++) out[i] = (unsigned char)(ct[i] ^ 0xFF);
    if (result_len) *result_len = ctl;
    return 0;
}
static NTSTATUS WINAPI mock_destroykey(BCRYPT_KEY_HANDLE h) { (void)h; return 0; }
static NTSTATUS WINAPI mock_createhash(BCRYPT_ALG_HANDLE a, BCRYPT_HASH_HANDLE *b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { (void)a;(void)c;(void)d;(void)e;(void)f;(void)g; *b = NULL; return 0; }
static NTSTATUS WINAPI mock_hashdata(BCRYPT_HASH_HANDLE h, PUCHAR d, ULONG l, ULONG f) { (void)h;(void)d;(void)l;(void)f; return 0; }
static NTSTATUS WINAPI mock_finishhash(BCRYPT_HASH_HANDLE h, PUCHAR o, ULONG ol, ULONG f) { (void)h;(void)o;(void)ol;(void)f; return 0; }
static NTSTATUS WINAPI mock_destroyhash(BCRYPT_HASH_HANDLE h) { (void)h; return 0; }
static NTSTATUS WINAPI mock_genrandom(BCRYPT_ALG_HANDLE a, PUCHAR b, ULONG c, ULONG d) { (void)a;(void)d; memset(b, 0xAB, c); return 0; }

static void install_mock_bcrypt(void) {
    bcrypt_api_t mock = {0};
    mock.pOpen = mock_open; mock.pClose = mock_close;
    mock.pSetProp = mock_setprop; mock.pGenKey = mock_genkey;
    mock.pDerive = mock_derive; mock.pDecrypt = mock_decrypt;
    mock.pDestroyKey = mock_destroykey; mock.pCreateHash = mock_createhash;
    mock.pHashData = mock_hashdata; mock.pFinishHash = mock_finishhash;
    mock.pDestroyHash = mock_destroyhash; mock.pGenRandom = mock_genrandom;
    mirage_bcrypt_api_install(&mock);
}

int main(void) {
    printf("=== test_chrome_bcrypt: BCrypt-path GCM status handling ===\n");

    install_mock_bcrypt();

    /* Valid v10 blob: 3 + 12 + ct + 16 tag. ct = 6 bytes. */
    unsigned char blob[3 + 12 + 6 + 16];
    memcpy(blob, "v10", 3);
    memset(blob + 3, 0x11, 12);   /* nonce */
    memset(blob + 15, 0xAA, 6);   /* ciphertext */
    memset(blob + 21, 0xBB, 16);  /* tag */
    unsigned char key[32] = {1};
    unsigned char out[64];
    size_t out_len = 0;
    /* Case 1: happy path sanity — mock decrypt succeeds */
    int rc = chrome_decrypt_password(blob, sizeof(blob), key, out, sizeof(out), &out_len);
    if (rc == 0 && out_len == 6 && out[0] == 0x55) TEST("bcrypt happy path");
    else { FAIL("bcrypt happy path"); printf("    rc=%d out_len=%zu\n", rc, out_len); }

    /* Case 2 (RED): auth-tag mismatch — pDecrypt returns failure NTSTATUS.
     * chrome_decrypt_password MUST return -1 and set *out_len = 0. */
    g_fail_decrypt = 1;
    rc = chrome_decrypt_password(blob, sizeof(blob), key, out, sizeof(out), &out_len);
    if (rc == -1) TEST("bcrypt auth-tag mismatch returns -1");
    else { FAIL("bcrypt auth-tag mismatch returns -1"); printf("    rc=%d (status was ignored)\n", rc); }
    if (out_len == 0) TEST("bcrypt auth failure zeroes out_len");
    else { FAIL("bcrypt auth failure zeroes out_len"); printf("    out_len=%zu\n", out_len); }

    printf("=== test_chrome_bcrypt: %d/%d PASSED ===\n", passed, passed + failed);
    return (failed == 0) ? 0 : 1;
}
