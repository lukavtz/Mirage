/*
 * rt_startup.c — process entry point without CRT startup.
 */
#include <windows.h>
#include <stddef.h>
#include <string.h>

int main(int argc, char **argv);

void __main(void) { /* MinGW sometimes references this */ }

void exit(int code) {
    ExitProcess((UINT)code);
}

void _exit(int code) {
    ExitProcess((UINT)code);
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

    const char *raw = GetCommandLineA();
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
    ExitProcess((UINT)code);
}
