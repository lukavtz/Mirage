#include "file_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

/* ── Read entire file into malloc'd buffer ────────────────────── */

unsigned char *read_file(const char *path, size_t *out_len) {
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

/* ── Path join ────────────────────────────────────────────────── */

char *path_join(const char *a, const char *b) {
    if (!a || !b) return NULL;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    char *out = (char *)malloc(la + 1 + lb + 1);
    if (!out) return NULL;
    memcpy(out, a, la);
    out[la] = PATH_SEP_CHAR;
    memcpy(out + la + 1, b, lb + 1);
    return out;
}

/* ── Check if directory exists ────────────────────────────────── */

int dir_exists(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

/* ── Check if file exists ─────────────────────────────────────── */

int file_exists(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

/* ── Extract basename from path ───────────────────────────────── */

const char *basename_of(const char *path) {
    const char *last = strrchr(path, PATH_SEP_CHAR);
    return last ? last + 1 : path;
}
