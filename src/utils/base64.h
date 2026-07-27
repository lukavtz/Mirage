#ifndef BASE64_H
#define BASE64_H
#include <stddef.h>
#include <stdint.h>

int base64_decode(const char *input, size_t input_len,
                  unsigned char *out, size_t out_max);

#endif
