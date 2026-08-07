/*
 * fuzz_runner.c — Simple corpus-walking fuzz harness for Windows/mingw.
 * Compiles with ASAN. Reads files from corpus dir, feeds to test function.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    *out_len = n;
    return buf;
}

#ifdef _WIN32
static int run_corpus(const char *corpus_dir, time_t deadline) {
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%s\\*", corpus_dir);
    wchar_t wpattern[1024];
    MultiByteToWideChar(CP_UTF8, 0, pattern, -1, wpattern, 1024);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (time(NULL) < deadline)
            LLVMFuzzerTestOneInput((const unsigned char *)"", 0);
        return 0;
    }
    int count = 0;
    do {
        if (time(NULL) >= deadline) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char fpath[1024];
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, fpath, sizeof(fpath), NULL, NULL);
        char full[2048];
        snprintf(full, sizeof(full), "%s\\%s", corpus_dir, fpath);
        size_t len = 0;
        unsigned char *data = read_file(full, &len);
        if (data) {
            LLVMFuzzerTestOneInput(data, len);
            free(data);
            count++;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return count;
}
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <corpus_dir> [max_seconds]\n", argv[0]);
        return 1;
    }
    int max_sec = (argc >= 3) ? atoi(argv[2]) : 60;
    time_t deadline = time(NULL) + max_sec;
    int iterations = 0;

    fprintf(stderr, "Fuzzing corpus: %s for %d seconds\n", argv[1], max_sec);

    while (time(NULL) < deadline) {
        int n = run_corpus(argv[1], deadline);
        iterations += n;
        if (n == 0) {
            unsigned char buf[4096];
            for (int i = 0; i < 4096; i++) buf[i] = (unsigned char)(rand() & 0xFF);
            LLVMFuzzerTestOneInput(buf, 4096);
            iterations++;
        }
    }

    fprintf(stderr, "Done. %d iterations in %d seconds.\n", iterations, max_sec);
    return 0;
}
