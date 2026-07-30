#ifndef MIRAGE_PEB_HIDE_H
#define MIRAGE_PEB_HIDE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mirage_hide_self — Corrupt the DOS header MZ signature of the
 * current executable to hide from module scanners.
 * Returns 1 on success, 0 on failure.
 */
int mirage_hide_self(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_PEB_HIDE_H */
