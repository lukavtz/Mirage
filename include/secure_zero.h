/*
 * secure_zero.h — Compiler-resistant memory zeroization.
 */
#ifndef MIRAGE_SECURE_ZERO_H
#define MIRAGE_SECURE_ZERO_H

#include <stddef.h>

/*
 * Zero memory in a way the compiler cannot optimize away.
 * Use after any operation involving keys, passwords, or
 * decrypted data that must not remain in the heap.
 */
void mirage_secure_zero(void *ptr, size_t len);

#endif /* MIRAGE_SECURE_ZERO_H */
