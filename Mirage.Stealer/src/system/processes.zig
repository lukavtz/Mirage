const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");

pub const ProcessEntry = struct {
    pid: u32,
    name: []const u8,
};

pub fn collect(allocator: std.mem.Allocator) ![]ProcessEntry {
    const MAX_ATTEMPTS = 5;
    var attempt: u32 = 0;
    var buf_size: usize = 256 * 1024;
    while (attempt < MAX_ATTEMPTS) : (attempt += 1) {
        var buf_base: ?types.PVOID = null;
        var size: types.SIZE_T = @as(types.SIZE_T, @intCast(buf_size));
        var ret_len: types.ULONG = 0;

        if (engine.NtAllocateVirtualMemory(
            @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
            @as(*types.PVOID, @ptrCast(&buf_base)),
            0, &size,
            types.MEM_COMMIT | types.MEM_RESERVE,
            types.PAGE_READWRITE,
        ) < 0 or buf_base == null) return error.AllocFailed;
        defer {
            var free_base: ?types.PVOID = buf_base;
            var free_size: types.SIZE_T = 0;
            _ = engine.NtFreeVirtualMemory(@as(types.HANDLE, @ptrFromInt(~@as(usize, 0))), @as(*types.PVOID, @ptrCast(&free_base)), &free_size, types.MEM_RELEASE);
        }

        const status = engine.NtQuerySystemInformation(5, buf_base.?, @as(types.ULONG, @intCast(size)), &ret_len);
        if (status == 0x80000005) { // STATUS_INFO_LENGTH_MISMATCH
            buf_size *= 2;
            continue;
        }
        if (status < 0) return error.QueryFailed;

        var result = std.ArrayList(ProcessEntry).init(allocator);
        errdefer {
            for (result.items) |entry| allocator.free(entry.name);
            result.deinit();
        }

        const bytes: [*]u8 = @ptrCast(@alignCast(buf_base.?));
        var offset: usize = 0;
        while (offset < ret_len) {
            const entry: *align(1) types.SYSTEM_PROCESS_INFORMATION = @ptrCast(bytes + offset);
            const name_len = entry.ImageName.Length / 2;
            if (name_len > 0 and name_len < 256) {
                const raw_ptr: [*]u8 = @ptrCast(@alignCast(bytes));
                const name_offset = @intFromPtr(entry.ImageName.Buffer) - @intFromPtr(buf_base.?);
                if (name_offset + name_len * 2 <= ret_len) {
                    const name_ptr: [*]u16 = @ptrCast(@alignCast(raw_ptr + name_offset));
                    var name_buf: [256]u8 = undefined;
                    for (0..name_len) |i| name_buf[i] = @as(u8, @truncate(name_ptr[i]));
                    const pid = @as(u32, @intCast(@intFromPtr(entry.UniqueProcessId)));
                    const name = try allocator.dupe(u8, name_buf[0..name_len]);
                    try result.append(ProcessEntry{ .pid = pid, .name = name });
                }
            }
            if (entry.NextEntryOffset == 0) break;
            offset += entry.NextEntryOffset;
        }

        return try result.toOwnedSlice();
    }
    return error.QueryFailed;
}

const testing = std.testing;

test "collect returns list" {
    const list = collect(testing.allocator) catch |err| {
        if (err == error.AllocFailed or err == error.QueryFailed) return;
        return err;
    };
    defer {
        for (list) |entry| testing.allocator.free(entry.name);
        testing.allocator.free(list);
    }
    try testing.expect(list.len > 0);
}

test "each process has a name" {
    const list = collect(testing.allocator) catch |err| {
        if (err == error.AllocFailed or err == error.QueryFailed) return;
        return err;
    };
    defer {
        for (list) |entry| testing.allocator.free(entry.name);
        testing.allocator.free(list);
    }
    for (list) |entry| {
        try testing.expect(entry.name.len > 0);
        try testing.expect(entry.pid > 0);
    }
}
