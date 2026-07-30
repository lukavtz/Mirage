/*
 * self_delete.h — Self-deletion module for zialfi
 *
 * Multi-level file deletion after execution.
 * Translated from Mirage Zig self_delete.zig.
 */

#ifndef ZIALFI_SELF_DELETE_H
#define ZIALFI_SELF_DELETE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SELF_DELETE_NONE    = 0,
    SELF_DELETE_LEVEL1  = 1,  /* NT API NtSetInformationFile delete */
    SELF_DELETE_LEVEL2  = 2,  /* MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT */
    SELF_DELETE_LEVEL3  = 3,  /* Batch script: taskkill + del + self-delete */
} SelfDeleteResult;

/*
 * self_delete_run — Attempt to delete the current executable.
 * Tries Level 1 (NT delete), Level 2 (MoveFileEx reboot), Level 3 (batch).
 * Returns the level that succeeded, or SELF_DELETE_NONE.
 */
SelfDeleteResult self_delete_run(void);

/*
 * self_delete_get_exe_path — Get the current executable's path (UTF-8).
 * Caller must free() the returned buffer.
 * Returns NULL on failure.
 */
char *self_delete_get_exe_path(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIALFI_SELF_DELETE_H */
