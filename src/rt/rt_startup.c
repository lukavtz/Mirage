/*
 * rt_startup.c — process entry point without CRT startup.
 */
#include <windows.h>
#include <stddef.h>

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
    int code = main(0, NULL);
    ExitProcess((UINT)code);
}
