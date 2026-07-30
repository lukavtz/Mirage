/*
 * inject.h — Process injection module for zialfi
 */
#ifndef ZIALFI_INJECT_H
#define ZIALFI_INJECT_H

#include <stddef.h>
#include <stdint.h>
#include <windows.h>

/* Injection methods */
typedef enum {
    INJECT_SHELLCODE = 1,
    INJECT_DLL = 2,
} inject_method_t;

/* Injection result */
typedef struct {
    int       success;
    DWORD     target_pid;
    char      target_name[64];
} inject_result_t;

inject_result_t inject_shellcode_to_target(const char *target_exe,
                                            const unsigned char *shellcode,
                                            size_t sc_len);

inject_result_t inject_dll_to_pid(DWORD pid, const char *dll_path);

DWORD inject_find_process(const char *name);

int inject_execute_local(const unsigned char *shellcode, size_t sc_len);

#endif
