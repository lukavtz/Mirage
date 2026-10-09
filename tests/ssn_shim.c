/*
 * ssn_shim.c — link shim for host-built test binaries that pull in
 * asm/mirage_stubs_v2.o (getPeb): the asm references the syscall
 * obfuscation global ssn_xor_key, which lives in src/syscalls/engine.c
 * and is not needed for crypto interop tests. Defined here (idempotent
 * value 0; the crypto paths never read it) so the test link closes.
 */
#include <stdint.h>
uint32_t ssn_xor_key = 0;
