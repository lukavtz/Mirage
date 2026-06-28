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

fn openRegKeyAt(allocator: std.mem.Allocator, path: []const u8) ?types.HANDLE {
    _ = allocator;
    var path_us: [512]u16 = undefined;
    @memset(&path_us, 0);
    for (path, 0..) |c, i| {
        if (i >= path_us.len) return null;
        path_us[i] = c;
    }
    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(path_us.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&path_us)),
    };
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

fn getFirstLocalIp(allocator: std.mem.Allocator) ![]const u8 {
    const adapter_base = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    var idx_buf: [8]u8 = undefined;

    for (0..10) |i| {
        const idx_str = try std.fmt.bufPrint(&idx_buf, "000{d}", .{i});
        var path_buf: [512]u8 = undefined;
        const adapter_path = try std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ adapter_base, idx_str });

        const adapter_key = openRegKeyAt(allocator, adapter_path) orelse continue;
        defer _ = engine.NtClose(adapter_key);

        const guid = readRegWideString(allocator, adapter_key, "NetCfgInstanceId") catch continue;
        defer allocator.free(guid);

        var tcpip_buf: [512]u8 = undefined;
        const tcpip_path = try std.fmt.bufPrint(&tcpip_buf, "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{s}", .{guid});
        const tcpip_key = openRegKeyAt(allocator, tcpip_path) orelse continue;
        defer _ = engine.NtClose(tcpip_key);

        if (readRegWideString(allocator, tcpip_key, "DhcpIPAddress")) |ip| {
            if (ip.len > 0 and !std.mem.eql(u8, ip, "0.0.0.0")) return ip;
            allocator.free(ip);
        } else |_| {
            if (readRegWideString(allocator, tcpip_key, "IPAddress")) |ip| {
                if (ip.len > 0 and !std.mem.eql(u8, ip, "0.0.0.0")) return ip;
                allocator.free(ip);
            } else |_| continue;
        }
    }
    return allocator.dupe(u8, "Unknown");
}

fn getMacAddress(allocator: std.mem.Allocator) ![]const u8 {
    const adapter_base = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    var idx_buf: [8]u8 = undefined;

    for (0..10) |i| {
        const idx_str = try std.fmt.bufPrint(&idx_buf, "000{d}", .{i});
        var path_buf: [512]u8 = undefined;
        const adapter_path = try std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ adapter_base, idx_str });

        const adapter_key = openRegKeyAt(allocator, adapter_path) orelse continue;
        defer _ = engine.NtClose(adapter_key);

        if (readRegWideString(allocator, adapter_key, "NetworkAddress")) |mac| {
            if (mac.len > 0) return mac;
            allocator.free(mac);
        } else |_| continue;
    }

    {
        const software_base = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
        var path_buf: [512]u8 = undefined;
        const if_path = try std.fmt.bufPrint(&path_buf, "{s}\\{s}\\{s}", .{ software_base, "{00000000-0000-0000-0000-000000000000}", "DhcpIPAddress" });
        _ = if_path;
    }

    return allocator.dupe(u8, "Unavailable");
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    var parts = std.ArrayList(u8).init(allocator);
    errdefer parts.deinit();

    {
        const tcpip_key = openRegKeyAt(allocator, "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters") orelse {
            try parts.appendSlice("Hostname: Unknown");
            try parts.appendSlice("\nLocal IP: Unknown");
            try parts.appendSlice("\nMAC: Unknown");
            try parts.appendSlice("\nPublic IP: Unknown");
            return try parts.toOwnedSlice();
        };
        defer _ = engine.NtClose(tcpip_key);

        const hostname = readRegWideString(allocator, tcpip_key, "Hostname") catch allocator.dupe(u8, "Unknown");
        defer allocator.free(hostname);
        try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "Hostname: {s}", .{hostname}));
    }

    const ip = getFirstLocalIp(allocator) catch allocator.dupe(u8, "Unknown");
    defer allocator.free(ip);
    try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "\nLocal IP: {s}", .{ip}));

    const mac = getMacAddress(allocator) catch allocator.dupe(u8, "Unavailable");
    defer allocator.free(mac);
    try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "\nMAC: {s}", .{mac}));

    try parts.appendSlice("\nPublic IP: Unavailable (requires HTTP request)");
    return try parts.toOwnedSlice();
}

const testing = std.testing;

test "collect returns formatted output" {
    const result = try collect(testing.allocator);
    defer testing.allocator.free(result);
    try testing.expect(result.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, result, 1, "Hostname:"));
}

test "getMacAddress returns string" {
    const mac = try getMacAddress(testing.allocator);
    defer testing.allocator.free(mac);
    try testing.expect(mac.len > 0);
}
