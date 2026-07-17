#!/usr/bin/env python3
"""Eidos Morpher - Build-time PE Morphing Tool"""

import struct, random, os, hashlib, argparse

PE32_PLUS_MAGIC = 0x20B
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

JUNK_PATTERNS = [
    b"\x90",
    b"\x48\x89\xc0",
    b"\x48\x89\xc9",
    b"\x48\x89\xd2",
    b"\x48\x89\xdb",
    b"\x48\x31\xc0",
    b"\x48\x31\xc9",
    b"\x48\x31\xd2",
    b"\x48\x31\xdb",
    b"\x48\x8d\x40\x00",
    b"\x48\x8d\x49\x00",
    b"\x48\x8d\x52\x00",
    b"\x48\x87\xc0",
    b"\x48\x87\xc9",
    b"\x48\x92",
    b"\x48\x0f\x1f\x00",
    b"\x48\x0f\x1f\x40\x00",
    b"\x66\x90",
    b"\x0f\x1f\x00",
    b"\x0f\x1f\x40\x00",
    b"\x66\x0f\x1f\x44\x00\x00",
]

SECTION_NAMES = {
    ".text": [".c0de", ".code0", ".text0", ".x64", ".code"],
    ".rdata": [".cnst", ".data0", ".rodata", ".rdoff"],
    ".data": [".vars", ".data1", ".bss0", ".heap"],
    ".rsrc": [".res0", ".rsrc0", ".resrc"],
    ".reloc": [".fix0", ".relc", ".patch"],
    ".pdata": [".pdta", ".pexc", ".eh"],
}

FAKE_IMPORTS = [
    ("user32.dll", ["MessageBoxW", "CreateWindowExW", "GetDC"]),
    ("gdi32.dll", ["BitBlt", "CreateCompatibleDC"]),
    ("wininet.dll", ["InternetOpenA", "InternetConnectA"]),
    ("crypt32.dll", ["CertOpenSystemStoreA", "CertCloseStore"]),
    ("advapi32.dll", ["RegOpenKeyExA", "RegQueryValueExA"]),
    ("shell32.dll", ["SHGetSpecialFolderPathW"]),
    ("ws2_32.dll", ["WSAStartup"]),
    ("comdlg32.dll", ["GetOpenFileNameW"]),
]


def align(v, a):
    return ((v + a - 1) // a) * a


class PEMorpher:
    def __init__(self, input_path, output_path=None, seed=None):
        self.input_path = input_path
        self.output_path = output_path or input_path
        self.rng = random.Random(seed if seed is not None else random.randint(0, 2**32))
        self.data = bytearray()
        self.pe_off = 0
        self.secs = []
        self.img_base = 0
        self.fa = 0x200
        self.sa = 0x1000
        self.entry = 0
        self.opt_sz = 0
        self.sec_start = 0

    def _read(self):
        with open(self.input_path, "rb") as f:
            self.data = bytearray(f.read())
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            raise ValueError("Not a valid PE file (no MZ signature or file too small)")
        self.pe_off = struct.unpack("<I", self.data[0x3C:0x40])[0]
        if (
            self.pe_off + 26 > len(self.data)
            or self.data[self.pe_off : self.pe_off + 4] != b"PE\x00\x00"
        ):
            raise ValueError("Not a valid PE file (no PE signature or truncated)")
        magic = struct.unpack("<H", self.data[self.pe_off + 24 : self.pe_off + 26])[0]
        if magic not in (PE32_PLUS_MAGIC, 0x10B):
            raise ValueError(f"Unrecognized PE magic: {magic:#x}")
        nsec = struct.unpack("<H", self.data[self.pe_off + 6 : self.pe_off + 8])[0]
        self.opt_sz = struct.unpack(
            "<H", self.data[self.pe_off + 20 : self.pe_off + 22]
        )[0]
        self.entry = struct.unpack(
            "<I", self.data[self.pe_off + 40 : self.pe_off + 44]
        )[0]
        self.fa = struct.unpack("<I", self.data[self.pe_off + 60 : self.pe_off + 64])[0]
        self.sa = struct.unpack("<I", self.data[self.pe_off + 56 : self.pe_off + 60])[0]
        if magic == PE32_PLUS_MAGIC:
            self.img_base = struct.unpack(
                "<Q", self.data[self.pe_off + 48 : self.pe_off + 56]
            )[0]
        else:
            self.img_base = struct.unpack(
                "<I", self.data[self.pe_off + 44 : self.pe_off + 48]
            )[0]
        self.sec_start = self.pe_off + 24 + self.opt_sz
        self.secs = []
        for i in range(nsec):
            o = self.sec_start + i * 40
            n = self.data[o : o + 8]
            self.secs.append(
                {
                    "nb": n,
                    "ns": n.rstrip(b"\x00").decode("ascii", errors="replace"),
                    "vs": struct.unpack("<I", self.data[o + 8 : o + 12])[0],
                    "va": struct.unpack("<I", self.data[o + 12 : o + 16])[0],
                    "rs": struct.unpack("<I", self.data[o + 16 : o + 20])[0],
                    "ro": struct.unpack("<I", self.data[o + 20 : o + 24])[0],
                    "ch": struct.unpack("<I", self.data[o + 36 : o + 40])[0],
                    "ho": o,
                }
            )

    def _dd_set(self, idx, rva, sz):
        o = self.pe_off + 120 + idx * 8
        struct.pack_into("<I", self.data, o, rva)
        struct.pack_into("<I", self.data, o + 4, sz)

    def _mk_junk(self, sz):
        r = bytearray()
        while len(r) < sz:
            p = self.rng.choice(JUNK_PATTERNS)
            t = min(len(p), sz - len(r))
            r.extend(p[:t])
        return bytes(r[:sz])

    def insert_junk_code(self):
        t = next((s for s in self.secs if s["ns"] == ".text"), None)
        if not t:
            return 0
        sz = self.rng.randint(65536, 131072)
        junk = self._mk_junk(sz)
        old = bytes(self.data[t["ro"] : t["ro"] + t["rs"]])
        code_end = len(old.rstrip(b"\x00"))
        new_raw = old[:code_end] + junk
        pad = align(len(new_raw), self.fa) - len(new_raw)
        new_raw += b"\x00" * pad
        delta = len(new_raw) - t["rs"]
        self.data = self.data[: t["ro"]] + new_raw + self.data[t["ro"] + t["rs"] :]
        t["rs"] = len(new_raw)
        t["vs"] = code_end + sz
        struct.pack_into("<I", self.data, t["ho"] + 8, t["vs"])
        struct.pack_into("<I", self.data, t["ho"] + 16, t["rs"])
        for s in self.secs:
            if s["ro"] > t["ro"]:
                s["ro"] += delta
                struct.pack_into("<I", self.data, s["ho"] + 20, s["ro"])
        return sz

    def rename_sections(self):
        c = 0
        for s in self.secs:
            ch = SECTION_NAMES.get(s["ns"])
            if ch:
                nb = self.rng.choice(ch).encode("ascii").ljust(8, b"\x00")[:8]
                self.data[s["ho"] : s["ho"] + 8] = nb
                s["ns"] = nb.rstrip(b"\x00").decode("ascii", errors="replace")
                c += 1
        return c

    def obfuscate_entry(self):
        t = next(
            (s for s in self.secs if s["ns"] in (".text", ".c0de", ".code0")), None
        )
        if not t:
            return False
        orig = self.img_base + self.entry
        st = bytearray()
        st += b"\x68" + struct.pack("<I", self.rng.randint(0, 0xFFFFFFFF))
        st.append(0x58)
        st += b"\x31\xc9"
        st += b"\x49\xbb" + struct.pack("<Q", orig)
        st += b"\x41\xff\xe3"
        off = t["ro"] + t["vs"] - 64
        self.data[off : off + len(st)] = st
        ne = t["va"] + (off - t["ro"])
        struct.pack_into("<I", self.data, self.pe_off + 40, ne)
        self.entry = ne
        return True

    def add_fake_imports(self):
        iid_b, nm_b, bn_b = bytearray(), bytearray(), bytearray()
        ilt_b, iat_b = bytearray(), bytearray()
        n_off, b_off, ni = 0, 0, len(FAKE_IMPORTS)
        iid_sz = 20 * (ni + 1)
        for dll, funcs in FAKE_IMPORTS:
            ilt_off = iid_sz + n_off + b_off
            iat_off = ilt_off + (len(funcs) + 1) * 8
            iid = struct.pack("<III", ilt_off, 0, iid_sz + n_off) + struct.pack(
                "<I", iat_off
            )
            iid_b.extend(iid)
            nb = dll.encode("ascii") + b"\x00"
            nm_b.extend(nb)
            for fn in funcs:
                be = (
                    struct.pack("<H", self.rng.randint(0, 0xFFFF))
                    + fn.encode("ascii")
                    + b"\x00"
                )
                bn_b.extend(be)
                rv = iid_sz + n_off + b_off
                ilt_b += struct.pack("<Q", rv)
                iat_b += struct.pack("<Q", rv)
                b_off += len(be)
            ilt_b += b"\x00" * 8
            iat_b += b"\x00" * 8
            n_off += len(nb)
        iid_b += b"\x00" * 20
        sec_data = (
            bytes(iid_b) + bytes(nm_b) + bytes(bn_b) + bytes(ilt_b) + bytes(iat_b)
        )
        vs = len(sec_data)
        sv = align(
            self.secs[-1]["va"] + max(self.secs[-1]["vs"], self.secs[-1]["rs"]), self.sa
        )
        sr = align(len(self.data), self.fa)
        rs = align(vs, self.fa)
        self.data += b"\x00" * (sr - len(self.data))
        self.data += sec_data + b"\x00" * (rs - vs)
        # Patch IID RVAs to absolute
        name_off = iid_sz
        for idx, (dll, funcs) in enumerate(FAKE_IMPORTS):
            eo = sr + idx * 20
            prev_nm = sum(len(d.encode("ascii")) + 1 for d, _ in FAKE_IMPORTS[:idx])
            prev_bn = sum(
                sum(len(fn.encode("ascii")) + 3 for fn in f) + 16
                for _, f in FAKE_IMPORTS[:idx]
            )
            ilt_rva = sv + iid_sz + prev_nm + prev_bn
            iat_rva = ilt_rva + (len(funcs) + 1) * 8
            nm_rva = sv + iid_sz + prev_nm
            struct.pack_into("<I", self.data, eo, ilt_rva)
            struct.pack_into("<I", self.data, eo + 12, nm_rva)
            struct.pack_into("<I", self.data, eo + 16, iat_rva)
        # Patch ILT/IAT entries
        data_off = sr + iid_sz
        data_off += sum(len(d.encode("ascii")) + 1 for d, _ in FAKE_IMPORTS)
        data_off += sum(
            sum(len(fn.encode("ascii")) + 3 for fn in f) for _, f in FAKE_IMPORTS
        )
        for _, funcs in FAKE_IMPORTS:
            for fn in funcs:
                cur = struct.unpack("<Q", self.data[data_off : data_off + 8])[0]
                if cur:
                    struct.pack_into("<Q", self.data, data_off, sv + cur)
                data_off += 8
            data_off += 8
        # Add section header
        idx = len(self.secs)
        hdr = self.sec_start + idx * 40
        self.data[hdr : hdr + 8] = b".mimp\x00\x00\x00"
        struct.pack_into("<I", self.data, hdr + 8, vs)
        struct.pack_into("<I", self.data, hdr + 12, sv)
        struct.pack_into("<I", self.data, hdr + 16, rs)
        struct.pack_into("<I", self.data, hdr + 20, sr)
        struct.pack_into("<I", self.data, hdr + 24, 0)
        struct.pack_into("<I", self.data, hdr + 28, 0)
        struct.pack_into("<H", self.data, hdr + 32, 0)
        struct.pack_into("<H", self.data, hdr + 34, 0)
        ch = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        struct.pack_into("<I", self.data, hdr + 36, ch)
        self.secs.append({"vs": vs, "va": sv, "rs": rs, "ro": sr})
        # Update headers
        n = struct.unpack("<H", self.data[self.pe_off + 6 : self.pe_off + 8])[0]
        struct.pack_into("<H", self.data, self.pe_off + 6, n + 1)
        new_hdr_end = self.sec_start + (n + 1) * 40
        new_soh = align(new_hdr_end, self.fa)
        struct.pack_into("<I", self.data, self.pe_off + 84, new_soh)
        struct.pack_into("<I", self.data, self.pe_off + 80, sv + align(vs, self.sa))
        self._dd_set(IMAGE_DIRECTORY_ENTRY_IMPORT, sv, iid_sz)
        return ni

    def append_overlay(self, overlay_path=None):
        if overlay_path:
            with open(overlay_path, "rb") as f:
                overlay_data = f.read()
            self.data += overlay_data
            return len(overlay_data)
        sz = self.rng.randint(3670016, 4194304)  # 3.5-4MB overlay
        self.data += bytes(self.rng.getrandbits(8) for _ in range(sz))
        return sz

    def uniqueness(self, a, b):
        mx = max(len(a), len(b))
        if mx == 0:
            return 0.0
        diffs = sum(1 for i in range(min(len(a), len(b))) if a[i] != b[i])
        return (diffs + abs(len(b) - len(a))) / mx * 100.0

    def morph(self, overlay_path=None):
        self._read()
        sha_b = hashlib.sha256(self.data).hexdigest()
        ob = bytes(self.data)
        osz = len(self.data)
        jb = self.insert_junk_code()
        rn = self.rename_sections()
        self.obfuscate_entry()
        fi = self.add_fake_imports()
        ov = self.append_overlay(overlay_path)
        sha_a = hashlib.sha256(self.data).hexdigest()
        pct = self.uniqueness(ob, bytes(self.data))
        with open(self.output_path, "wb") as f:
            f.write(self.data)
        return {
            "original_size": osz,
            "final_size": len(self.data),
            "junk_bytes": jb,
            "sections_renamed": rn,
            "fake_imports_added": fi,
            "overlay_size": ov,
            "sha256_before": sha_b,
            "sha256_after": sha_a,
            "uniqueness_pct": pct,
        }


def main():
    ap = argparse.ArgumentParser(description="Eidos Morpher - PE Morphing Tool")
    ap.add_argument("input", help="Input PE file")
    ap.add_argument("-o", "--output", help="Output file path")
    ap.add_argument("--overlay", help="DLL overlay file to append")
    ap.add_argument("--seed", type=int, help="Random seed")
    a = ap.parse_args()
    m = PEMorpher(a.input, a.output or a.input, seed=a.seed)
    s = m.morph(a.overlay)
    print("Morphing complete:")
    print(f"  Original size: {s['original_size']} bytes")
    print(f"  Final size: {s['final_size']} bytes")
    print(f"  Junk code inserted: {s['junk_bytes']} bytes")
    print(f"  Sections renamed: {s['sections_renamed']}")
    print(f"  Fake imports added: {s['fake_imports_added']}")
    print(f"  Overlay size: {s['overlay_size']} bytes")
    print(f"  SHA256 before: {s['sha256_before']}")
    print(f"  SHA256 after: {s['sha256_after']}")
    print(f"  Uniqueness: {s['uniqueness_pct']:.1f}%")
    if s["uniqueness_pct"] < 75:
        print("  WARNING: Uniqueness below 75% target")


if __name__ == "__main__":
    main()
