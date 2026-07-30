#ifndef ZIALFI_SOCKS5_H
#define ZIALFI_SOCKS5_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define closesocket(s) close(s)
#endif

#ifdef ENABLE_SOCKS5

int socks5_connect(const char *proxy_host, uint16_t proxy_port,
                   const char *target_host, uint16_t target_port,
                   SOCKET *out_sock);

const char *socks5_resolve_via_tor(void);

#endif /* ENABLE_SOCKS5 */
#endif /* ZIALFI_SOCKS5_H */
