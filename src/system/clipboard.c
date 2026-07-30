#include "clipboard.h"
#include "config.h"
#include <windows.h>

#ifdef ENABLE_CLIPBOARD

#define CF_UNICODETEXT 13

/* Convert a single Unicode codepoint to UTF-8, write to *out, return bytes written */
static int u32_to_utf8(unsigned int cp, unsigned char *out) {
    if (cp < 0x80) {
        out[0] = (unsigned char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (unsigned char)(0xC0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 0x3F));
        return 2;
    } else {
        out[0] = (unsigned char)(0xE0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (unsigned char)(0x80 | (cp & 0x3F));
        return 3;
    }
}

int clipboard_get_text(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return -1;
    buf[0] = '\0';

    if (!OpenClipboard(NULL))
        return -1;

    HANDLE h_mem = GetClipboardData(CF_UNICODETEXT);
    if (!h_mem) {
        CloseClipboard();
        return -1;
    }

    const wchar_t *wstr = (const wchar_t *)GlobalLock(h_mem);
    if (!wstr) {
        CloseClipboard();
        return -1;
    }

    /* Walk the wide string and convert to UTF-8 */
    size_t pos = 0;
    const wchar_t *p = wstr;

    while (*p && pos < buf_len - 1) {
        unsigned int cp = (unsigned int)*p;

        /* Handle surrogate pairs */
        if (cp >= 0xD800 && cp <= 0xDBFF && p[1] >= 0xDC00 && p[1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + ((unsigned int)p[1] - 0xDC00);
            p++;
        }
        p++;

        unsigned char utf8[4];
        int n = u32_to_utf8(cp, utf8);
        if (pos + (size_t)n >= buf_len - 1)
            break;

        for (int i = 0; i < n; i++)
            buf[pos++] = (char)utf8[i];
    }
    buf[pos] = '\0';

    GlobalUnlock(h_mem);
    CloseClipboard();
    return 0;
}

unsigned int clipboard_get_sequence(void) {
    return (unsigned int)GetClipboardSequenceNumber();
}

#endif /* ENABLE_CLIPBOARD */
