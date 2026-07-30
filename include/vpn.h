#ifndef VPN_H
#define VPN_H

#include <stddef.h>

/* Collect all VPN client configurations into output_dir.
   Returns total number of files copied, or -1 on error. */
int vpn_collect(const char *output_dir);

#endif /* VPN_H */
