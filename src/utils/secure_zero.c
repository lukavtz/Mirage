/*
 * secure_zero.c — Compiler-resistant memory zeroization.
 *
 * memset(ptr, 0, len) can be optimized away when the compiler
 * detects the buffer is not read after the call. This function
 * uses volatile writes to guarantee zeroing.
 */

#include "secure_zero.h"

void mirage_secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
        *p++ = 0;
}
