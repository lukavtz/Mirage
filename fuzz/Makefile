FUZZ_CC = clang
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address -I../include -I../src/parsers -I../src/utils -std=c11

.PHONY: all clean

all: fuzz_lz4 fuzz_sqlite fuzz_json

fuzz_lz4: fuzz_lz4.c ../src/utils/lz4.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I../src/utils -o fuzz_lz4 fuzz_lz4.c ../src/utils/lz4.c

fuzz_sqlite: fuzz_sqlite.c ../src/parsers/sqlite.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o fuzz_sqlite fuzz_sqlite.c ../src/parsers/sqlite.c

fuzz_json: fuzz_json.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -DTEST_JSON_EXTRACT_STANDALONE -o fuzz_json fuzz_json.c

clean:
	rm -f fuzz_lz4 fuzz_sqlite fuzz_json fuzz_lz4.exe fuzz_sqlite.exe fuzz_json.exe
