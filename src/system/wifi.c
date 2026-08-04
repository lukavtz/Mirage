#include "wifi.h"
#include "config.h"
#include "nt_types.h"
#include <string.h>
#include <stdio.h>

/* Collect WiFi passwords via netsh */
int mirage_collect_wifi_passwords(char *output, size_t outlen) {
    (void)output;
    (void)outlen;
    dbg_printf("[!] WiFi enumeration not implemented\n");
    return 0;
}

/* Get WiFi profile list */
int mirage_get_wifi_profiles(char *buf, size_t buflen) {
    (void)buf;
    (void)buflen;
    dbg_printf("[!] WiFi enumeration not implemented\n");
    return 0;
}
