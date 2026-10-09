#!/usr/bin/env python3
"""Test for make_polymorphic.rewrite_archive_seed.

Runs against a COPY of panel/internal/services/archive_decrypt.go in a temp
dir — the real repo file is never touched. Verifies:
  1. the archiveSeed constant is rewritten to the new seed (LE + 4 zero bytes)
  2. the rest of the file is untouched
  3. a missing anchor fails loudly (SystemExit)
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import make_polymorphic as mp

SRC = os.path.join(mp.ROOT, "panel", "internal", "services", "archive_decrypt.go")


def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)
    print(f"ok: {msg}")
def main():
    with open(SRC, "r", encoding="utf-8") as f:
        original = f.read()

    tmp = tempfile.mkdtemp(prefix="seed_sync_")
    copy = os.path.join(tmp, "archive_decrypt.go")
    shutil.copyfile(SRC, copy)
    try:
        # 1. rewrite on a copy
        mp.rewrite_archive_seed(copy, 0x32D2C189)
        with open(copy, "r", encoding="utf-8") as f:
            after = f.read()

        expected = "var archiveSeed = []byte{137, 193, 210, 50, 0, 0, 0, 0}"
        check(expected in after, f"seed rewritten to LE bytes: {expected}")

        # 2. rest of file identical
        orig_lines = original.replace(
            "var archiveSeed = []byte{148, 229, 117, 173, 0, 0, 0, 0}",
            expected,
        )
        # comments above the constant stay as they were (only the var line changes)
        check(after == orig_lines, "only the archiveSeed line changed")

        # 3. idempotence: rewriting again with the same seed is a no-op
        mp.rewrite_archive_seed(copy, 0x32D2C189)
        with open(copy, "r", encoding="utf-8") as f:
            check(f.read() == after, "rewrite is idempotent")

        # 4. missing anchor fails loudly
        empty = os.path.join(tmp, "empty.go")
        with open(empty, "w", encoding="utf-8") as f:
            f.write("package services\n")
        try:
            mp.rewrite_archive_seed(empty, 0x11223344)
            check(False, "missing anchor should SystemExit")
        except SystemExit:
            check(True, "missing anchor raises SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 5. the real file was never touched
    with open(SRC, "r", encoding="utf-8") as f:
        check(f.read() == original, "real archive_decrypt.go untouched")

    print("ALL GREEN")


if __name__ == "__main__":
    main()
