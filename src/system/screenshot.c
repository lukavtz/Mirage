#include "screenshot.h"
#include "config.h"
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

/* Write BMP to file */
static int write_bmp_file(const char *path, const unsigned char *data, size_t len) {
    HANDLE hf;
    DWORD  written;

    hf = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return -1;

    WriteFile(hf, data, (DWORD)len, &written, NULL);
    CloseHandle(hf);
    return (written == (DWORD)len) ? 0 : -1;
}

/* Build BMP from raw BGRA pixel data */
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

    /* BMPFileHeader */
    BMPFileHeader *fh = (BMPFileHeader *)bmp;
    fh->bfType      = 0x4D42; /* "BM" */
    fh->bfSize      = (unsigned int)file_size;
    fh->bfReserved1 = 0;
    fh->bfReserved2 = 0;
    fh->bfOffBits   = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);

    /* BMPInfoHeader */
    BMPInfoHeader *ih = (BMPInfoHeader *)(bmp + sizeof(BMPFileHeader));
    ih->biSize        = sizeof(BMPInfoHeader);
    ih->biWidth       = width;
    ih->biHeight      = -height; /* top-down */
    ih->biPlanes      = 1;
    ih->biBitCount    = 32;
    ih->biCompression = 0; /* BI_RGB */
    ih->biSizeImage   = (unsigned int)img_size;

    /* Pixel data (BGRA, bottom-up from GDI, but height is negative = top-down) */
    unsigned char *dst = bmp + sizeof(BMPFileHeader) + sizeof(BMPInfoHeader);
    for (int y = 0; y < height; y++) {
        memcpy(dst + y * stride, pixels + y * row_bytes, (size_t)row_bytes);
    }

    *out_size = (size_t)file_size;
    return bmp;
}

/* Capture screen into BGRA buffer. Caller must free *pixels. */
static int capture_screen(unsigned char **pixels, int *w, int *h) {
    HDC hScreen    = GetDC(NULL);
    HDC hMemDC     = CreateCompatibleDC(hScreen);
    int cx         = GetSystemMetrics(SM_CXSCREEN);
    int cy         = GetSystemMetrics(SM_CYSCREEN);

    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, cx, cy);
    HGDIOBJ hOld    = SelectObject(hMemDC, hBitmap);

    BitBlt(hMemDC, 0, 0, cx, cy, hScreen, 0, 0, SRCCOPY);

    BITMAPINFO bi;
    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = cx;
    bi.bmiHeader.biHeight      = -cy; /* top-down */
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    size_t img_bytes = (size_t)cx * (size_t)cy * 4;
    unsigned char *buf = (unsigned char *)malloc(img_bytes);
    if (!buf) {
        SelectObject(hMemDC, hOld);
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreen);
        return -1;
    }

    GetDIBits(hMemDC, hBitmap, 0, cy, buf, &bi, DIB_RGB_COLORS);

    SelectObject(hMemDC, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreen);

    *pixels = buf;
    *w = cx;
    *h = cy;
    return 0;
}

/* ── Public API ────────────────────────────────────────────── */

int screenshot_capture(const char *output_path) {
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
