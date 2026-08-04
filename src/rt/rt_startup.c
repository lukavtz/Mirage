/*
 * rt_startup.c — process entry point without CRT startup.
 */
#include <windows.h>
#include <stddef.h>
#include <string.h>
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"

typedef void (WINAPI *pExitProcess)(UINT);
typedef char * (WINAPI *pGetCommandLineA)(void);

static struct {
    pExitProcess    pEP;
    pGetCommandLineA pGCLA;
    int             ready;
} g_start_api;

static int ensure_start(void) {
    if (g_start_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_ExitProcess, ENC_EXITPROCESS_LEN, fn);
    g_start_api.pEP = (pExitProcess)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetCommandLineA, ENC_GETCOMMANDLINEA_LEN, fn);
    g_start_api.pGCLA = (pGetCommandLineA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_start_api.pEP || !g_start_api.pGCLA) return 0;
    g_start_api.ready = 1;
    return 1;
}

int main(int argc, char **argv);

void __main(void) { /* MinGW sometimes references this */ }

void exit(int code) {
    if (ensure_start())
        g_start_api.pEP((UINT)code);
    for (;;) ;
}

void _exit(int code) {
    if (ensure_start())
        g_start_api.pEP((UINT)code);
    for (;;) ;
}

int abs(int v) {
    return (v < 0) ? -v : v;
}

/* Custom entry: no CRT init, straight into main. */
void mainCRTStartup(void) {
    /* Parse minimal argv from GetCommandLineA */
    static char cmdline[2048];
    static char *argv_buf[16];
    int argc = 0;

    const char *raw = ensure_start() ? g_start_api.pGCLA() : NULL;
    if (raw) {
        size_t len = strlen(raw);
        if (len < sizeof(cmdline)) {
            memcpy(cmdline, raw, len + 1);
            /* Simple tokenizer: split on spaces, respect quotes */
            char *p = cmdline;
            while (*p && argc < 15) {
                while (*p == ' ' || *p == '\t') p++;
                if (!*p) break;
                argv_buf[argc++] = p;
                if (*p == '"') {
                    p++;
                    argv_buf[argc - 1] = p;
                    while (*p && *p != '"') p++;
                    if (*p) *p++ = '\0';
                } else {
                    while (*p && *p != ' ' && *p != '\t') p++;
                    if (*p) *p++ = '\0';
                }
            }
        }
    }
    argv_buf[argc] = NULL;

    int code = main(argc, argv_buf);
    if (ensure_start())
        g_start_api.pEP((UINT)code);
    for (;;) ;
}
