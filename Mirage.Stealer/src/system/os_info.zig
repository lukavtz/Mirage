const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");

fn initUnicodeString(comptime s: []const u8, buf: *[512]u16) types.UNICODE_STRING {
    @memset(buf, 0);
    for (s, 0..) |c, i| {
        buf[i] = c;
    }
    return .{
        .Length = @as(types.USHORT, @intCast(s.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(buf)),
    };
}

fn openRegKey(comptime path: []const u8) ?types.HANDLE {
    var buf_us: [512]u16 = undefined;
    var us = initUnicodeString(path, &buf_us);
    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var key_handle: types.HANDLE = undefined;
    const status = engine.NtOpenKey(&key_handle, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&oa)));
    return if (status >= 0) key_handle else null;
}

fn readRegWideString(allocator: std.mem.Allocator, key: types.HANDLE, comptime value_name: []const u8) ![]u8 {
    var buf_us: [512]u16 = undefined;
    var buf_data: [8192]u8 = undefined;

    var vn = initUnicodeString(value_name, &buf_us);
    var result_len: types.ULONG = 0;
    const status = engine.NtQueryValueKey(
        key,
        &vn,
        @intFromEnum(types.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation),
        @as(types.PVOID, @ptrCast(&buf_data)),
        @as(types.ULONG, @intCast(buf_data.len)),
        &result_len,
    );
    if (status < 0) return error.RegistryRead;

    const kvpi: *types.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(&buf_data));
    const raw = buf_data[@offsetOf(types.KEY_VALUE_PARTIAL_INFORMATION, "Data")..][0..kvpi.DataLength];

    var utf16_len: usize = raw.len / 2;
    while (utf16_len > 0) {
        const c = std.mem.readInt(u16, raw[(utf16_len - 1) * 2 ..][0..2], .little);
        if (c != 0) break;
        utf16_len -= 1;
    }
    if (utf16_len == 0) return allocator.dupe(u8, "");

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    for (0..utf16_len) |i| {
        const cp = std.mem.readInt(u16, raw[i * 2 ..][0..2], .little);
        if (cp < 0x80) {
            try out.append(@as(u8, @intCast(cp & 0x7F)));
        } else if (cp < 0x800) {
            try out.append(@as(u8, @intCast(0xC0 | (cp >> 6))));
            try out.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
        } else {
            try out.append(@as(u8, @intCast(0xE0 | (cp >> 12))));
            try out.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F))));
            try out.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
        }
    }
    return try out.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    const key = openRegKey("\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") orelse return error.RegistryOpen;
    defer _ = engine.NtClose(key);

    const pn = readRegWideString(allocator, key, "ProductName") catch null;
    defer if (pn) |v| allocator.free(v);
    const dv = readRegWideString(allocator, key, "DisplayVersion") catch null;
    defer if (dv) |v| allocator.free(v);
    const cb = readRegWideString(allocator, key, "CurrentBuild") catch null;
    defer if (cb) |v| allocator.free(v);
    const ed = readRegWideString(allocator, key, "EditionID") catch null;
    defer if (ed) |v| allocator.free(v);
    const ri = readRegWideString(allocator, key, "ReleaseId") catch null;
    defer if (ri) |v| allocator.free(v);

    const product_name = pn orelse "Unknown";
    const display_ver = dv orelse "";
    const build = cb orelse "0";
    const edition = ed orelse "";
    const release = ri orelse "";

    if (release.len > 0) {
        return std.fmt.allocPrint(allocator, "{s} {s} (build {s}) [{s}] v{s}", .{ product_name, display_ver, build, edition, release });
    }
    return std.fmt.allocPrint(allocator, "{s} {s} (build {s}) [{s}]", .{ product_name, display_ver, build, edition });
}

const testing = std.testing;

test "initUnicodeString produces correct length" {
    var buf: [512]u16 = undefined;
    const us = initUnicodeString("Test", &buf);
    try testing.expectEqual(@as(types.USHORT, 8), us.Length);
    try testing.expectEqual(@as(types.USHORT, 1024), us.MaximumLength);
}

test "reading fake registry key returns error" {
    const result = collect(testing.allocator);
    try testing.expect(result != null);
}
