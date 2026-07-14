const std = @import("std");
const builtin = @import("builtin");

pub const OsTag = enum {
    Windows,
    Linux,
    macOS,
};

pub fn currentOs() OsTag {
    return switch (builtin.os.tag) {
        .windows => .Windows,
        .linux => .Linux,
        .macos => .macOS,
        else => @compileError("unsupported OS: " ++ @tagName(builtin.os.tag)),
    };
}

pub const FileHandle = switch (builtin.os.tag) {
    .windows => *anyopaque,
    .linux => i32,
    .macos => i32,
    else => @compileError("unsupported OS"),
};

pub const DirEntry = struct {
    name: []const u8,
    kind: DirEntryKind,
};

pub const DirEntryKind = enum {
    file,
    directory,
    symlink,
    unknown,
};

test "currentOs returns Windows on this system" {
    try std.testing.expectEqual(OsTag.Windows, currentOs());
}

test "OsTag enum has all expected variants" {
    switch (@typeInfo(OsTag)) {
        .@"enum" => |info| try std.testing.expect(info.fields.len == 3),
        else => unreachable,
    }
    comptime {
        try std.testing.expect(std.mem.eql(u8, @tagName(OsTag.Windows), "Windows"));
        try std.testing.expect(std.mem.eql(u8, @tagName(OsTag.Linux), "Linux"));
        try std.testing.expect(std.mem.eql(u8, @tagName(OsTag.macOS), "macOS"));
    }
}

test "FileHandle type resolves per platform" {
    try std.testing.expect(@sizeOf(FileHandle) == @sizeOf(*anyopaque));
}
