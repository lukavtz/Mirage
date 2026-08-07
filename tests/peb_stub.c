#include <stdint.h>
void* getPeb(void) {
    void* peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}
