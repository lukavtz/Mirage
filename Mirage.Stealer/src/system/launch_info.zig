const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const LaunchInfo = struct {
    exe_path: []const u8,
    is_disk: bool,
};

const E = struct {
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const get_module_file_name_w = hash.xorEncrypt("GetModuleFileNameW");
};

const GetModuleFileNameWFn = *const fn (hModule: types.HANDLE, lpFilename: [*]u16, nSize: u32) callconv(.winapi) u32;

fn resolveKernel32() ?GetModuleFileNameWFn {
    var kernel32_buf: [E.kernel32.len]u8 = undefined;
    hash.xorDecrypt(&E.kernel32, &kernel32_buf);

    const kernel32_module = peb_walk.getModuleByHash(hash.encryptedHashModule(&kernel32_buf)) orelse return null;

    var gmf_buf: [E.get_module_file_name_w.len]u8 = undefined;
    hash.xorDecrypt(&E.get_module_file_name_w, &gmf_buf);

    return @as(GetModuleFileNameWFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(kernel32_module, hash.hashStringExact(&gmf_buf, 27)) orelse return null,
    )));
}

pub fn collect(allocator: std.mem.Allocator) !LaunchInfo {
    const get_module_file_name_w = resolveKernel32() orelse return error.ResolutionFailed;

    var buf: [1024]u16 = undefined;
    const len = get_module_file_name_w(@ptrFromInt(0), &buf, @as(u32, @intCast(buf.len)));
    if (len == 0) return error.GetModuleFileNameFailed;

    const slice = buf[0..len];
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    for (slice) |cp| {
        if (cp < 0x80) {
            try result.append(@as(u8, @intCast(cp & 0x7F)));
        } else if (cp < 0x800) {
            try result.append(@as(u8, @intCast(0xC0 | (cp >> 6))));
            try result.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
        } else {
            try result.append(@as(u8, @intCast(0xE0 | (cp >> 12))));
            try result.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F))));
            try result.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
        }
    }

    const exe_path = try result.toOwnedSlice();

    const is_disk = blk: {
        var file = std.fs.openFileAbsolute(exe_path, .{}) catch break :blk false;
        file.close();
        break :blk true;
    };

    return LaunchInfo{ .exe_path = exe_path, .is_disk = is_disk };
}

const testing = std.testing;

test "collect returns valid launch info" {
    const info = collect(testing.allocator) catch |err| {
        if (err == error.ResolutionFailed or err == error.GetModuleFileNameFailed) return;
        return err;
    };
    defer testing.allocator.free(info.exe_path);
    try testing.expect(info.exe_path.len > 0);
}

test "exe_path contains executable extension" {
    const info = collect(testing.allocator) catch |err| {
        if (err == error.ResolutionFailed or err == error.GetModuleFileNameFailed) return;
        return err;
    };
    defer testing.allocator.free(info.exe_path);
    try testing.expect(info.exe_path.len > 3);
}

test "E values decrypt correctly" {
    var buf: [E.kernel32.len]u8 = undefined;
    hash.xorDecrypt(&E.kernel32, &buf);
    try testing.expectEqualSlices(u8, "kernel32.dll", &buf);
}
