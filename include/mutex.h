/*
 * mutex.h — Single-instance mutex for Mirage-C
 *
 * Creates a named event object via NtCreateEvent to enforce
 * single-instance execution. If the event already exists
 * (STATUS_OBJECT_NAME_COLLISION), the function returns 0
 * indicating another instance is running.
 */

#ifndef MIRAGE_MUTEX_H
#define MIRAGE_MUTEX_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_ensure_mutex — Create a single-instance event mutex.
 *
 * Derives an event name from the build seed, creates a
 * NotificationEvent via NtCreateEvent. Returns 1 if this is
 * the first instance (event created successfully), 0 if another
 * instance already holds the mutex (STATUS_OBJECT_NAME_COLLISION
 * = 0xC000004E) or on error.
 */
int mirage_ensure_mutex(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_MUTEX_H */
