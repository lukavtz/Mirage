/*
 * test_crypto_mock.c -- Crypto tests via bcrypt mock seam
 * Build: gcc -Wall -Wextra -O2 -Iinclude -Isrc -Isrc/crypto -Isrc/types \
 *        -Isrc/utils -Isrc/parsers -std=c11 -DZIALFI_TEST_MODE \
 *        -o tests/test_crypto_mock tests/test_crypto_mock.c \
 *        src/crypto/bcrypt_peb.c src/types/hash.c src/types/export_resolve.c \
 *        src/types/peb.c src/utils/base64.c -lbcrypt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZIALFI_TEST_MODE
#include <windows.h>
#include <bcrypt.h>
#include "bcrypt_peb.h"
#include "peb.h"
#include "hash.h"
#include "base64.h"

#define TEST(name) do { printf("  PASS: %s\n", name); passed++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s -- %s\n", name, msg); failed++; } while(0)

/* Stub for NASM getPeb */
void *getPeb(void) { return NULL; }

/* ── Pure-C SHA256 for mock ─────────────────────────────────── */
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block[64];
    size_t total = len + 1 + 8; /* +1 for 0x80, +8 for length */
    size_t padded = ((total + 63) / 64) * 64;

    for (size_t off = 0; off < padded; off += 64) {
        memset(block, 0, 64);
        for (int i = 0; i < 64; i++) {
            size_t idx = off + i;
            if (idx < len) block[i] = data[idx];
            else if (idx == len) block[i] = 0x80;
            else if (idx >= padded - 8) {
                uint64_t bits = (uint64_t)len * 8;
                block[i] = (uint8_t)(bits >> (56 - (i - (padded - 8)) * 8));
            }
        }
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|((uint32_t)block[i*4+2]<<8)|block[i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + sha256_k[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) { out[i*4]=(h[i]>>24); out[i*4+1]=(h[i]>>16); out[i*4+2]=(h[i]>>8); out[i*4+3]=h[i]; }
}

/* ── Mock bcrypt implementations ────────────────────────────── */
/* Track calls for verification */
static int g_open_calls = 0;
static int g_createhash_calls = 0;
static int g_hashdata_calls = 0;
static int g_finishhash_calls = 0;

static NTSTATUS WINAPI mock_open(BCRYPT_ALG_HANDLE *h, LPCWSTR a, LPCWSTR b, ULONG c) {
    (void)a;(void)b;(void)c; *h = (BCRYPT_ALG_HANDLE)0x1234; g_open_calls++; return 0;
}
static NTSTATUS WINAPI mock_close(BCRYPT_ALG_HANDLE h, ULONG f) { (void)h;(void)f; return 0; }
static NTSTATUS WINAPI mock_setprop(BCRYPT_ALG_HANDLE h, LPCWSTR p, PUCHAR v, ULONG vs, ULONG f) { (void)h;(void)p;(void)v;(void)vs;(void)f; return 0; }
static NTSTATUS WINAPI mock_genkey(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE *b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return 0; }
static NTSTATUS WINAPI mock_derive(BCRYPT_ALG_HANDLE a, PUCHAR pw, ULONG pwlen, PUCHAR salt, ULONG saltlen, ULONGLONG iters, PUCHAR out, ULONG outlen, ULONG flags) {
    /* Simple mock PBKDF2: SHA256(pw || salt) repeated */
    (void)a;(void)iters;(void)flags;
    size_t total = pwlen + saltlen;
    uint8_t *tmp = malloc(total);
    if (!tmp) return (NTSTATUS)0xC0000017; /* STATUS_NO_MEMORY */
    memcpy(tmp, pw, pwlen);
    memcpy(tmp + pwlen, salt, saltlen);
    uint8_t hash[32];
    sha256(tmp, total, hash);
    free(tmp);
    size_t copy = outlen < 32 ? outlen : 32;
    memcpy(out, hash, copy);
    return 0;
}
static NTSTATUS WINAPI mock_decrypt(BCRYPT_KEY_HANDLE a, PUCHAR b, ULONG c, PVOID d, PUCHAR e, ULONG f, PUCHAR g, ULONG h, ULONG *i, ULONG j) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j; return 0; }
static NTSTATUS WINAPI mock_destroykey(BCRYPT_KEY_HANDLE h) { (void)h; return 0; }
static NTSTATUS WINAPI mock_createhash(BCRYPT_ALG_HANDLE a, BCRYPT_HASH_HANDLE *b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { (void)a;(void)c;(void)d;(void)e;(void)f;(void)g; *b = (BCRYPT_HASH_HANDLE)0x5678; g_createhash_calls++; return 0; }
static NTSTATUS WINAPI mock_hashdata(BCRYPT_HASH_HANDLE h, PUCHAR d, ULONG l, ULONG f) { (void)h;(void)d;(void)l;(void)f; g_hashdata_calls++; return 0; }
static NTSTATUS WINAPI mock_finishhash(BCRYPT_HASH_HANDLE h, PUCHAR out, ULONG outlen, ULONG f) {
    (void)h;(void)f;
    /* Return a deterministic hash */
    uint8_t hash[32];
    sha256((uint8_t*)"mock", 4, hash);
    size_t copy = outlen < 32 ? outlen : 32;
    memcpy(out, hash, copy);
    g_finishhash_calls++;
    return 0;
}
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
    int passed = 0, failed = 0;
    printf("=== test_crypto_mock: Crypto mock tests ===\n");

    install_mock_bcrypt();

    /* Test 1: bcrypt API resolves via mock */
    {
        const bcrypt_api_t *api = mirage_bcrypt_api();
        if (api && api->ready && api->pOpen == mock_open) TEST("bcrypt API resolves");
        else FAIL("bcrypt API resolves", "not ready");
    }

    /* Test 2: mock_open tracks calls */
    {
        g_open_calls = 0;
        const bcrypt_api_t *api = mirage_bcrypt_api();
        BCRYPT_ALG_HANDLE h;
        NTSTATUS st = api->pOpen(&h, L"SHA256", NULL, 0);
        if (st == 0 && g_open_calls == 1) TEST("mock_open tracks calls");
        else FAIL("mock_open tracks calls", "unexpected");
    }

    /* Test 3: mock_derive computes deterministic output */
    {
        const bcrypt_api_t *api = mirage_bcrypt_api();
        uint8_t out[32] = {0};
        NTSTATUS st = api->pDerive((BCRYPT_ALG_HANDLE)0x1234,
            (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1000, out, 32, 0);
        if (st == 0) {
            /* Verify non-zero output (SHA256 of "password"+"salt" is deterministic) */
            int all_zero = 1;
            for (int i = 0; i < 32; i++) if (out[i] != 0) { all_zero = 0; break; }
            if (!all_zero) TEST("mock_derive deterministic");
            else FAIL("mock_derive", "all zeros");
        } else FAIL("mock_derive", "failed");
    }

    /* Test 4: mock_derive different inputs = different outputs */
    {
        const bcrypt_api_t *api = mirage_bcrypt_api();
        uint8_t out1[32], out2[32];
        api->pDerive((BCRYPT_ALG_HANDLE)0x1234, (PUCHAR)"pass1", 5, (PUCHAR)"salt", 4, 1000, out1, 32, 0);
        api->pDerive((BCRYPT_ALG_HANDLE)0x1234, (PUCHAR)"pass2", 5, (PUCHAR)"salt", 4, 1000, out2, 32, 0);
        if (memcmp(out1, out2, 32) != 0) TEST("derive different inputs differ");
        else FAIL("derive different inputs", "same output");
    }

    /* Test 5: mock_genrandom fills buffer */
    {
        const bcrypt_api_t *api = mirage_bcrypt_api();
        uint8_t buf[64];
        memset(buf, 0, 64);
        NTSTATUS st = api->pGenRandom(NULL, buf, 64, 0);
        if (st == 0 && buf[0] == 0xAB && buf[63] == 0xAB) TEST("genrandom fills buffer");
        else FAIL("genrandom", "unexpected pattern");
    }

    /* Test 6: hash pipeline works */
    {
        g_createhash_calls = 0; g_hashdata_calls = 0; g_finishhash_calls = 0;
        const bcrypt_api_t *api = mirage_bcrypt_api();
        BCRYPT_HASH_HANDLE hh;
        api->pCreateHash((BCRYPT_ALG_HANDLE)0x1234, &hh, NULL, 0, NULL, 0, 0);
        api->pHashData(hh, (PUCHAR)"hello", 5, 0);
        uint8_t hash[32];
        api->pFinishHash(hh, hash, 32, 0);
        api->pDestroyHash(hh);
        if (g_createhash_calls == 1 && g_hashdata_calls == 1 && g_finishhash_calls == 1)
            TEST("hash pipeline call tracking");
        else FAIL("hash pipeline", "wrong call count");
    }

    /* Test 7: SHA256 known vector ("abc") */
    {
        uint8_t hash[32];
        sha256((uint8_t*)"abc", 3, hash);
        /* SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
        const uint8_t expected[] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                                     0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
        if (memcmp(hash, expected, 32) == 0) TEST("SHA256 abc known vector");
        else FAIL("SHA256 abc", "hash mismatch");
    }

    printf("=== test_crypto_mock: %d/%d PASSED ===\n", passed, passed + failed);
    return failed ? 1 : 0;
}
