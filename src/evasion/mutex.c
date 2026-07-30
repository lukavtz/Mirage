/*
 * mutex.c — Single-instance mutex for Mirage-C
 *
 * Direct translation of Zig src/evasion/mutex.zig.
 * Derives an event name from MIRAGE_SEED and creates a
 * NotificationEvent via NtCreateEvent. The event name format
 * is "XXXX-XXXX-XXXX" derived from the seed value.
 */

#include "mutex.h"
#include "engine.h"
#include "nt_types.h"
#include "config.h"
#include <string.h>

#ifdef ENABLE_MUTEX

/* ── STATUS_OBJECT_NAME_COLLISION ─────────────────────────── */
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC000004E)

/* ── Helper: derive event name from seed ──────────────────── */

static void derive_event_name(char* buf, size_t buf_size) {
    if (buf_size < 12) return;

    static const char hex[] = "0123456789ABCDEF";
    uint32_t h = MIRAGE_SEED;

    buf[0]  = hex[(h >> 28) & 0xF];
    buf[1]  = hex[(h >> 24) & 0xF];
    buf[2]  = '-';
    buf[3]  = hex[(h >> 20) & 0xF];
    buf[4]  = hex[(h >> 16) & 0xF];
    buf[5]  = '-';
    buf[6]  = hex[(h >> 12) & 0xF];
    buf[7]  = hex[(h >> 8)  & 0xF];
    buf[8]  = '-';
    buf[9]  = hex[(h >> 4)  & 0xF];
    buf[10] = hex[h & 0xF];
    buf[11] = 0;
}

/* ── mirage_ensure_mutex ──────────────────────────────────── */

int mirage_ensure_mutex(void) {
    char name_buf[64];
    derive_event_name(name_buf, sizeof(name_buf));

    size_t name_len = strlen(name_buf);

    /* Build wide string */
    WCHAR us_buf[512];
    memset(us_buf, 0, sizeof(us_buf));
    for (size_t i = 0; i < name_len && i < 511; i++)
        us_buf[i] = (WCHAR)name_buf[i];

    UNICODE_STRING us;
    us.Length = (USHORT)(name_len * 2);
    us.MaximumLength = (USHORT)sizeof(us_buf);
    us.Buffer = us_buf;

    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE event_handle = NULL;
    NTSTATUS status = mirage_NtCreateEvent(
        &event_handle,
        SEMAPHORE_ALL_ACCESS,  /* 0x1F0003 */
        &oa,
        (ULONG)NotificationEvent,  /* 0 */
        0  /* InitialState = FALSE */
    );

    if (status == STATUS_OBJECT_NAME_COLLISION)
        return 0;  /* Another instance is running */

    if (status < 0)
        return 0;

    /* Event created successfully — we are the first instance.
     * Keep the handle open for the lifetime of the process. */
    mirage_NtClose(event_handle);
    return 1;
}

#endif /* ENABLE_MUTEX */
