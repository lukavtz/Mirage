/*
 * ws2_peb.h — PEB-resolved Winsock API function pointers
 *
 * Shared singleton for all ws2_32.dll calls.
 * Resolves ws2_32.dll via PEB-walk + hash-based export table parsing.
 */
#ifndef MIRAGE_WS2_PEB_H
#define MIRAGE_WS2_PEB_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (WSAAPI *pWSAStartup)(WORD, LPWSADATA);
typedef int (WSAAPI *pWSACleanup)(void);
typedef SOCKET (WSAAPI *pWSASocketW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef SOCKET (WSAAPI *psocket)(int, int, int);
typedef int (WSAAPI *pconnect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *psend)(SOCKET, const char *, int, int);
typedef int (WSAAPI *precv)(SOCKET, char *, int, int);
typedef int (WSAAPI *pclosesocket)(SOCKET);
typedef int (WSAAPI *pbind)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *plisten)(SOCKET, int);
typedef SOCKET (WSAAPI *paccept)(SOCKET, struct sockaddr *, int *);
typedef int (WSAAPI *psetsockopt)(SOCKET, int, int, const char *, int);
typedef int (WSAAPI *pgetsockname)(SOCKET, struct sockaddr *, int *);
typedef int (WSAAPI *pgetaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
typedef void (WSAAPI *pfreeaddrinfo)(PADDRINFOA);
typedef u_short (WSAAPI *phtons)(u_short);
typedef u_long (WSAAPI *phtonl)(u_long);
typedef u_short (WSAAPI *pntohs)(u_short);

typedef struct {
    pWSAStartup     pStartup;
    pWSACleanup     pCleanup;
    pWSASocketW     pWSASocketW;
    psocket         psocket;
    pconnect        pconnect;
    psend           psend;
    precv           precv;
    pclosesocket    pclosesocket;
    pbind           pbind;
    plisten         plisten;
    paccept         paccept;
    psetsockopt     psetsockopt;
    pgetsockname    pgetsockname;
    pgetaddrinfo    pgetaddrinfo;
    pfreeaddrinfo   pfreeaddrinfo;
    phtons          phtons;
    phtonl          phtonl;
    pntohs          pntohs;
    int ready;
} ws2_api_t;

const ws2_api_t *mirage_ws2_api(void);

#ifdef __cplusplus
}
#endif

#endif /* MIRAGE_WS2_PEB_H */
