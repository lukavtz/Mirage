#ifndef ZIALFI_RT_H
#define ZIALFI_RT_H

#include <windows.h>
#include <stddef.h>
#include <stdarg.h>

/*
 * Minimal C runtime for zialfi — removes msvcrt.dll dependency.
 * Implemented: memory, string, conversion, formatting, file I/O,
 * process entry. Declarations here match what callers use from
 * the standard headers (stdlib.h/stdio.h/string.h).
 */

/* ═══════ Minimal FILE (opaque to callers; stdio.h sees it as opaque) ═══ */

typedef struct _iobuf {
    HANDLE handle;
    int    mode;   /* 0=read, 1=write, 2=append */
    int    error;
    int    eof;
} FILE;

#ifndef EOF
#define EOF (-1)
#endif
#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

#endif /* ZIALFI_RT_H */
