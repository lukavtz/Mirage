/*
 * persistence.h — Persistence mechanisms for zialfi
 *
 * Registry Run Key, Task Scheduler, Startup Folder, WMI.
 * Translated from Mirage Zig persistence modules.
 */

#ifndef ZIALFI_PERSISTENCE_H
#define ZIALFI_PERSISTENCE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PERSIST_OK       = 0,
    PERSIST_PARTIAL  = 1,
    PERSIST_NO_ADMIN = 2,
    PERSIST_FAILED   = 3,
} PersistResult;

typedef enum {
    PERSIST_METHOD_REGISTRY      = 0,
    PERSIST_METHOD_TASK_SCHED    = 1,
    PERSIST_METHOD_STARTUP_DIR   = 2,
    PERSIST_METHOD_WMI           = 3,
} PersistMethod;

/*
 * persistence_install — Try all methods in order, stop on first success.
 * exe_path: path to the executable to persist (UTF-8).
 * Returns PERSIST_OK if any method succeeded, PERSIST_FAILED otherwise.
 */
PersistResult persistence_install(const char *exe_path);

/*
 * persistence_uninstall — Remove all persistence artifacts.
 * Returns PERSIST_OK if at least one method succeeded.
 */
PersistResult persistence_uninstall(void);

/*
 * persistence_is_installed — Check if any persistence method is active.
 * Returns 1 if installed, 0 otherwise.
 */
int persistence_is_installed(void);

/* ── Individual methods ─────────────────────────────────────── */

/* Registry: write under HKLM\...\Run or HKCU\...\Run */
int persist_registry_install(const char *exe_path);
int persist_registry_uninstall(void);
int persist_registry_is_installed(void);

/* Task Scheduler: schtasks /create ... */
int persist_scheduler_install(const char *exe_path);
int persist_scheduler_uninstall(void);

/* Startup Folder: copy exe to %APPDATA%\...\Startup */
int persist_startup_install(const char *exe_path);
int persist_startup_uninstall(void);

/* WMI: PowerShell __EventFilter + ActiveScriptEventConsumer */
int persist_wmi_install(const char *exe_path);
int persist_wmi_uninstall(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIALFI_PERSISTENCE_H */
