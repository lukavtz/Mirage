/*
 * test_stack_spoof_offsets.c — layout invariants for spoof_call frame
 *
 * Host-only (no Windows deps). Asserts the frame layout declared in
 * include/stack_spoof_layout.h:
 *   - arg slots: a3 at +0x28 .. a11 at +0x68 (win64 shadow+retaddr math)
 *   - non-volatile save region disjoint from the callee arg window
 *     [rsp+0x28 .. rsp+0x60] after `sub rsp, SSL_FRAME_SIZE`
 *   - arg stash region strictly above rsp+0x60 (unreachable by target)
 *   - .inc and .h declare identical constants (parses the .inc textually)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stack_spoof_layout.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
} while (0)

int main(void) {
    /* 1. Arg slot arithmetic: [rbp+8]=retaddr, +0x10..0x28 shadow, a3=+0x28 */
    CHECK(SSL_ARG3_OFF == 0x28, "arg3 slot must be frame+0x28");
    CHECK(SSL_ARG4_OFF == SSL_ARG3_OFF + 0x08, "arg4 = arg3+8");
    CHECK(SSL_ARG5_OFF == SSL_ARG3_OFF + 0x10, "arg5 = arg3+0x10");
    CHECK(SSL_ARG11_OFF == SSL_ARG3_OFF + 0x40, "arg11 = frame+0x68");
    CHECK(SSL_ARG11_OFF == 0x68, "arg11 slot must be frame+0x68");

    /* 2. Frame size = chain + callee window */
    CHECK(SSL_FRAME_SIZE == SSL_CHAIN_SIZE + SSL_CALLEE_WINDOW,
          "frame size = chain + callee window");

    /* 3. Regions in our own frame (rbp-relative, below rbp):
     *    after sub rsp, FRAME_SIZE:  rsp = rbp - SSL_FRAME_SIZE.
     *    arg window = [rsp+0x28 .. rsp+0x60]
     *    NV saves   = [rbp-NV_BASE-7*8 .. rbp-NV_BASE+8]  (8 qwords)
     *    stashes    = [rbp-STASH_BASE-6*8 .. rbp-STASH_BASE+8]
     * Both regions must be ABOVE (lower address than) rsp+0x60. */
    uintptr_t rsp = (uintptr_t)0x100000 - SSL_FRAME_SIZE;  /* rbp = 0x100000 */
    uintptr_t rbp = 0x100000;

    /* NV save region occupies [rbp - NV_BASE - (NV_COUNT-1)*8, rbp - NV_BASE + 8] */
    uintptr_t nv_lo = rbp - SSL_NV_SAVE_BASE - (SSL_NV_COUNT - 1) * 8;
    uintptr_t nv_hi = rbp - SSL_NV_SAVE_BASE + 8;
    /* arg window the target can touch: [rsp+0x28, rsp+0x60] */
    uintptr_t win_lo = rsp + 0x28;
    uintptr_t win_hi = rsp + 0x60;

    CHECK(nv_hi < win_lo,
          "non-volatile saves must lie below (lower than) the callee arg window");
    if (!(nv_hi < win_lo))
        printf("  nv region [0x%lx..0x%lx] overlaps arg window [0x%lx..0x%lx]\n",
               (unsigned long)nv_lo, (unsigned long)nv_hi,
               (unsigned long)win_lo, (unsigned long)win_hi);

    /* Stash region: above (lower address) rsp+0x60 too */
    uintptr_t st_lo = rbp - SSL_STASH_BASE - (SSL_STASH_COUNT - 1) * 8;
    uintptr_t st_hi = rbp - SSL_STASH_BASE + 8;
    CHECK(st_hi < win_lo, "stash region must lie below the callee arg window");
    if (!(st_hi < win_lo))
        printf("  stash region [0x%lx..0x%lx] overlaps arg window [0x%lx..0x%lx]\n",
               (unsigned long)st_lo, (unsigned long)st_hi,
               (unsigned long)win_lo, (unsigned long)win_hi);

    /* Stash must not collide with NV saves either (regions are adjacent:
     * stash ends exactly where NV saves begin; allow touching) */
    CHECK(st_hi <= nv_lo, "stash region must not overlap NV save region");

    /* 4. .inc consistency: parse NASM defines, compare with C macros.
     * The .asm %includes this file, so a mismatch means the asm and the
     * test disagree about the layout. */
    {
        FILE *f = fopen("include/stack_spoof_layout.inc", "r");
        CHECK(f != NULL, "include/stack_spoof_layout.inc must exist");
        if (f) {
            char line[256];
            const struct { const char *name; long val; } expect[] = {
                {"SSL_ARG3_OFF", SSL_ARG3_OFF},
                {"SSL_ARG4_OFF", SSL_ARG4_OFF},
                {"SSL_ARG5_OFF", SSL_ARG5_OFF},
                {"SSL_ARG6_OFF", SSL_ARG6_OFF},
                {"SSL_ARG7_OFF", SSL_ARG7_OFF},
                {"SSL_ARG8_OFF", SSL_ARG8_OFF},
                {"SSL_ARG9_OFF", SSL_ARG9_OFF},
                {"SSL_ARG10_OFF", SSL_ARG10_OFF},
                {"SSL_ARG11_OFF", SSL_ARG11_OFF},
                {"SSL_CHAIN_SIZE", SSL_CHAIN_SIZE},
                {"SSL_CALLEE_WINDOW", SSL_CALLEE_WINDOW},
                {"SSL_FRAME_SIZE", SSL_FRAME_SIZE},
                {"SSL_NV_COUNT", SSL_NV_COUNT},
                {"SSL_NV_SAVE_BASE", SSL_NV_SAVE_BASE},
                {"SSL_NV_SAVE_SIZE", SSL_NV_SAVE_SIZE},
                {"SSL_STASH_COUNT", SSL_STASH_COUNT},
                {"SSL_STASH_BASE", SSL_STASH_BASE},
                {"SSL_STASH_SIZE", SSL_STASH_SIZE},
            };
            size_t n = sizeof(expect) / sizeof(expect[0]);
            size_t found = 0;
            while (fgets(line, sizeof(line), f)) {
                for (size_t i = 0; i < n; i++) {
                    char def[64];
                    snprintf(def, sizeof(def), "%%define %s ", expect[i].name);
                    size_t dl = strlen(def);
                    if (strncmp(line, def, dl) == 0) {
                        long v = strtol(line + dl, NULL, 0);
                        CHECK(v == expect[i].val, def);
                        if (v != expect[i].val)
                            printf("  %s: .inc=0x%lx .h=0x%lx\n", expect[i].name,
                                   v, expect[i].val);
                        found++;
                    }
                }
            }
            fclose(f);
            CHECK(found == n, "all .inc constants present in .h comparison");
        }
    }

    /* 5. ASM consistency: spoof_call must %include the shared layout and
     * load arg3 from SSL_ARG3_OFF..arg11 from SSL_ARG11_OFF. The old asm
     * hard-coded [rbp+0x58] for arg3 (0x30 too high) — this check is the
     * regression lock. */
    {
        FILE *f = fopen("asm/stack_spoof_stubs.asm", "r");
        CHECK(f != NULL, "asm/stack_spoof_stubs.asm must exist");
        if (f) {
            char buf[16384];
            size_t got = fread(buf, 1, sizeof(buf) - 1, f);
            buf[got] = 0;
            fclose(f);
            CHECK(strstr(buf, "%include \"stack_spoof_layout.inc\"") != NULL,
                  "asm must %include the shared layout .inc");
            CHECK(strstr(buf, "[rbp + SSL_ARG3_OFF]") != NULL,
                  "asm must load arg3 via SSL_ARG3_OFF");
            CHECK(strstr(buf, "[rbp + SSL_ARG11_OFF]") != NULL,
                  "asm must load arg11 via SSL_ARG11_OFF");
            /* old broken offsets must be gone */
            CHECK(strstr(buf, "[rbp + 0x58]") == NULL,
                  "old wrong arg3 offset [rbp+0x58] must not appear");
            CHECK(strstr(buf, "[rbp + 0x98]") == NULL,
                  "old wrong arg11 offset [rbp+0x98] must not appear");
            /* non-volatile saves must use the shared NV base */
            CHECK(strstr(buf, "SSL_NV_SAVE_BASE") != NULL,
                  "asm must place non-volatile saves via SSL_NV_SAVE_BASE");
            /* arg window writes: must not use [rbp-56] style old stashes */
            CHECK(strstr(buf, "[rbp - 56]") == NULL,
                  "old arg stash [rbp-56] must not appear");
            CHECK(strstr(buf, "[rbp - 96]") == NULL,
                  "old arg stash [rbp-96] must not appear");
        }
    }

    if (fails) { printf("=== test_stack_spoof_offsets: %d FAILURES ===\n", fails); return 1; }
    printf("=== test_stack_spoof_offsets PASSED ===\n");
    return 0;
}
