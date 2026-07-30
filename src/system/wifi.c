#include "wifi.h"
#include "nt_types.h"
#include <string.h>
#include <stdio.h>

/* Collect WiFi passwords via netsh */
int mirage_collect_wifi_passwords(char *output, size_t outlen) {
    (void)output;
    (void)outlen;
    /* TODO: implement WiFi profile enumeration via netsh */
    return 0;
}

/* Get WiFi profile list */
int mirage_get_wifi_profiles(char *buf, size_t buflen) {
    (void)buf;
    (void)buflen;
    /* TODO: implement via WlanEnumInterfaces + WlanGetProfile */
    return 0;
}
