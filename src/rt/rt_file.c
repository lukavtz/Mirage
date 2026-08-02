/*
 * rt_file.c — minimal FILE I/O via Win32. No CRT.
 * Supports the modes used in the codebase: "rb", "w", "a".
 */
#include "rt.h"

void *malloc(size_t n);
void free(void *p);
size_t strlen(const char *s);

FILE *fopen(const char *path, const char *mode) {
    if (!path || !mode) return NULL;
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

    HANDLE h = CreateFileA(path, access, share, NULL, disposition,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    if (fmode == 2) {
        LARGE_INTEGER li = { 0 };
        SetFilePointerEx(h, li, NULL, FILE_END);
    }

    FILE *f = malloc(sizeof(FILE));
    if (!f) {
        CloseHandle(h);
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
    CloseHandle(f->handle);
    free(f);
    return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    if (!f || size == 0)
        return 0;
    DWORD total = (DWORD)(size * nmemb);
    DWORD rd = 0;
    if (!ReadFile(f->handle, ptr, total, &rd, NULL)) {
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
    if (!WriteFile(f->handle, ptr, total, &wr, NULL)) {
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
    if (!SetFilePointerEx(f->handle, li, NULL, move)) {
        f->error = 1;
        return -1;
    }
    f->eof = 0;
    return 0;
}

long ftell(FILE *f) {
    LARGE_INTEGER cur = { 0 };
    LARGE_INTEGER pos;
    if (!SetFilePointerEx(f->handle, cur, &pos, FILE_CURRENT))
        return -1L;
    return (long)pos.QuadPart;
}

int fflush(FILE *f) {
    if (f && f->handle != INVALID_HANDLE_VALUE)
        FlushFileBuffers(f->handle);
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
    if (!WriteFile(f->handle, s, (DWORD)len, &wr, NULL)) {
        f->error = 1;
        return EOF;
    }
    return 0;
}
