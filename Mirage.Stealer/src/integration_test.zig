const std = @import("std");
const archive_crypt = @import("crypto/archive_crypt.zig");
const zip_mod = @import("network/zip.zig");

var pass_count: usize = 0;
var fail_count: usize = 0;

fn check(name: []const u8, ok: bool) void {
    if (ok) { std.debug.print("[PASS] {s}\n", .{name}); pass_count += 1; }
    else { std.debug.print("[FAIL] {s}\n", .{name}); fail_count += 1; }
}

pub fn main() void {
    std.debug.print("=== Eidos Integration Tests ===\n\n", .{});
    pass_count = 0; fail_count = 0;

    // 1. ZIP roundtrip
    {
        const allocator = std.heap.page_allocator;
        var z = zip_mod.ZipWriter.init(allocator) catch { check("ZIP: init failed", false); return; };
        defer z.deinit();
        z.addFile("test.txt", "Hello, World!") catch unreachable;
        z.addFile("data.bin", "\x00\x01\x02\x03") catch unreachable;
        const archive = z.finalize() catch { check("ZIP: finalize failed", false); return; };
        check("ZIP: archive non-empty", archive.len > 40);
        check("ZIP: PK signature", std.mem.readInt(u32, archive[0..4], .little) == 0x04034B50);
        check("ZIP: EOCD signature", std.mem.readInt(u32, archive[archive.len-22..][0..4], .little) == 0x06054B50);
        check("ZIP: multiple files", archive.len > 60);
    }

    // 2. Crypto pipeline
    {
        const plaintext = "Sensitive data for encryption test";
        var enc_buf: [1024]u8 = undefined; var dec_buf: [1024]u8 = undefined;
        const encrypted = archive_crypt.encryptArchive(plaintext, &enc_buf) orelse { check("CRYPTO: encrypt failed", false); return; };
        check("CRYPTO: ciphertext > plaintext", encrypted.len > plaintext.len);
        const decrypted = archive_crypt.decryptArchive(encrypted, &dec_buf) orelse { check("CRYPTO: decrypt failed", false); return; };
        check("CRYPTO: roundtrip matches", std.mem.eql(u8, plaintext, decrypted));
    }

    // 3. Tamper detection
    {
        const plaintext = "Data integrity test";
        var enc_buf: [1024]u8 = undefined; var dec_buf: [1024]u8 = undefined;
        const encrypted = archive_crypt.encryptArchive(plaintext, &enc_buf) orelse { check("TAMPER: encrypt failed", false); return; };
        var tampered: [1024]u8 = undefined;
        @memcpy(tampered[0..encrypted.len], encrypted);
        tampered[encrypted.len - 1] ^= 1;
        const result = archive_crypt.decryptArchive(tampered[0..encrypted.len], &dec_buf);
        check("TAMPER: modified ciphertext rejected", result == null);
    }

    // 4. Empty data
    {
        var enc_buf: [64]u8 = undefined; var dec_buf: [64]u8 = undefined;
        const encrypted = archive_crypt.encryptArchive("", &enc_buf) orelse { check("EMPTY: encrypt failed", false); return; };
        const decrypted = archive_crypt.decryptArchive(encrypted, &dec_buf) orelse { check("EMPTY: decrypt failed", false); return; };
        check("EMPTY: empty roundtrip", decrypted.len == 0);
    }

    // 5. Full pipeline: report → ZIP → encrypt → decrypt → verify
    {
        const report = "OS: Windows 10\nCPU: 4 cores\nRAM: 16 GB\nBrowser: Chrome\nPassword: test123";
        var z = zip_mod.ZipWriter.init(std.heap.page_allocator) catch { check("PIPE: ZIP init failed", false); return; };
        defer z.deinit();
        z.addFile("report.txt", report) catch unreachable;
        const archive = z.finalize() catch { check("PIPE: ZIP finalize failed", false); return; };
        check("PIPE: archive size > 30", archive.len > 30);

        var enc_buf: [1024 * 1024]u8 = undefined; var dec_buf: [1024 * 1024]u8 = undefined;
        const encrypted = archive_crypt.encryptArchive(archive, &enc_buf) orelse { check("PIPE: encrypt failed", false); return; };
        check("PIPE: encrypted", encrypted.len > 0);
        const decrypted = archive_crypt.decryptArchive(encrypted, &dec_buf) orelse { check("PIPE: decrypt failed", false); return; };
        check("PIPE: data integrity", std.mem.eql(u8, decrypted, archive));
        check("PIPE: complete", true);
    }

    std.debug.print("\n=== Results: {d} passed, {d} failed ===\n", .{pass_count, fail_count});
}
