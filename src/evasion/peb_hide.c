#include "peb_hide.h"
#include "config.h"

#ifdef ENABLE_PEB_HIDE
#include <windows.h>

/*
 * mirage_hide_self — Corrupt DOS header MZ signature to hide from
 * module scanners. Destroys e_magic at image base without touching
 * the fragile PEB LDR linked lists.
 */
int mirage_hide_self(void) {
    HMODULE mod = GetModuleHandleW(NULL);
    if (!mod) return 0;

    unsigned char *dos = (unsigned char *)mod;
    DWORD old;
    if (VirtualProtect(dos, 0x1000, PAGE_READWRITE, &old)) {
        dos[0] ^= dos[1];
        VirtualProtect(dos, 0x1000, old, &old);
        return 1;
    }
    return 0;
}

#else
int mirage_hide_self(void) { return 0; }
#endif
