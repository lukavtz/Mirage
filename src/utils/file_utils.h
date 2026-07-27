#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h>

#ifdef _WIN32
#define PATH_SEP "\\"
#define PATH_SEP_CHAR '\\'
#else
#define PATH_SEP "/"
#define PATH_SEP_CHAR '/'
#endif

char *path_join(const char *a, const char *b);
unsigned char *read_file(const char *path, size_t *out_len);
int dir_exists(const char *path);
int file_exists(const char *path);
const char *basename_of(const char *path);

#endif /* FILE_UTILS_H */
