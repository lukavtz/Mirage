const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");

pub fn wipeTempDirectory(allocator: std.mem.Allocator) void {
    const temp_path = std.process.getEnvVarOwned(allocator, "TEMP") catch return;
    defer allocator.free(temp_path);

    var dir = std.fs.openDirAbsolute(temp_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (true) {
        const entry = iter.next() catch break;
        const e = entry orelse break;
        if (e.kind != .file) continue;
        const full_path = std.fs.path.join(allocator, &[_][]const u8{ temp_path, e.name }) catch continue;
        defer allocator.free(full_path);
        _ = tryDeleteFile(full_path);
    }
}

fn tryDeleteFile(path: []const u8) void {
    var us_buf: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < path.len and i < us_buf.len) : (i += 1) us_buf[i] = path[i];
    us_buf[i] = 0;

    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };

    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    _ = engine.NtDeleteFile(@as(types.PVOID, @ptrCast(&oa)));
}

test "wipeTempDirectory no crash" {
    wipeTempDirectory(std.testing.allocator);
}

test "tryDeleteFile no crash" {
    tryDeleteFile("C:\\__nonexistent_test_file__");
}
