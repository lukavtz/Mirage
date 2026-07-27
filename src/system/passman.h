#ifndef PASSMAN_H
#define PASSMAN_H

#include <stddef.h>

// Collect password manager data from known paths
// Returns number of files collected, -1 on error
int passman_collect(const char *output_dir);

#endif
