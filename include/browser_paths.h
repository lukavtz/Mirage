#ifndef BROWSER_PATHS_H
#define BROWSER_PATHS_H

#include <stddef.h>

typedef struct {
    const char *name;
    const char *path_suffix;
    int use_roaming; // 0 = LOCALAPPDATA, 1 = APPDATA
} BrowserPath;

// Get all Chromium browser paths (58 browsers)
const BrowserPath *get_chromium_browsers(size_t *count);

// Get all Gecko browser paths (10 browsers)  
const BrowserPath *get_gecko_browsers(size_t *count);

#endif
