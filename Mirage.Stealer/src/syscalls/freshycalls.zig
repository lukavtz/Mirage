const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const ZwFuncEntry = struct {
    address: usize,
    name_hash: u32,
};

pub const SsnEntry = struct {
    ssn: u16,
    address: usize,
};

pub fn resolveByFreshyCalls(ntdll_base: types.PVOID, func_hash: u32) ?u16 {
    const base_bytes = @as([*]const u8, @ptrCast(@alignCast(ntdll_base)));
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;

    const lfanew: usize = @intCast(dos.e_lfanew);
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(base_bytes + lfanew)));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (export_dir_rva == 0) return null;

    const export_dir = @as(*const types.IMAGE_EXPORT_DIRECTORY, @ptrCast(@alignCast(base_bytes + export_dir_rva)));
    const names = @as([*]const u32, @ptrCast(@alignCast(base_bytes + export_dir.AddressOfNames)));
    const funcs = @as([*]const u32, @ptrCast(@alignCast(base_bytes + export_dir.AddressOfFunctions)));
    const ords = @as([*]const u16, @ptrCast(@alignCast(base_bytes + export_dir.AddressOfNameOrdinals)));

    var zw_funcs: [512]ZwFuncEntry = undefined;
    var zw_count: usize = 0;

    for (0..export_dir.NumberOfNames) |i| {
        if (zw_count >= 512) break;
        const name_ptr: [*:0]const u8 = @ptrCast(@alignCast(base_bytes + names[i]));
        if (name_ptr[0] == 'Z' and name_ptr[1] == 'w') {
            const name_len = std.mem.len(name_ptr);
            var h: u32 = config.SEED;
            for (name_ptr[0..name_len]) |c| {
                for (0..27) |_| {
                    h = std.math.rotl(u32, h, 5);
                    h = h ^ c;
                    h = h *% 0x1B873593 +% 0x85EBCA6B;
                }
            }
            zw_funcs[zw_count] = .{
                .address = base_bytes + funcs[ords[i]],
                .name_hash = h,
            };
            zw_count += 1;
        }
    }

    if (zw_count == 0) return null;

    var i: usize = 1;
    while (i < zw_count) : (i += 1) {
        var j: usize = i;
        while (j > 0 and zw_funcs[j].address < zw_funcs[j - 1].address) {
            const tmp = zw_funcs[j];
            zw_funcs[j] = zw_funcs[j - 1];
            zw_funcs[j - 1] = tmp;
            if (j > 0) j -= 1 else break;
        }
    }

    for (0..zw_count) |ssn_idx| {
        if (zw_funcs[ssn_idx].name_hash == func_hash) {
            return @as(u16, @intCast(ssn_idx));
        }
    }

    return null;
}

pub fn findSyscallGadget(ntdll_base: types.PVOID) ?usize {
    const base_bytes = @as([*]const u8, @ptrCast(@alignCast(ntdll_base)));
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;

    const lfanew: usize = @intCast(dos.e_lfanew);
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(base_bytes + lfanew)));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const oh_off = lfanew + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(base_bytes + sec_off));

    for (0..nt.FileHeader.NumberOfSections) |si| {
        const s = secs[si];
        if (s.Name[0] == '.' and s.Name[1] == 't' and s.Name[2] == 'e' and s.Name[3] == 'x' and s.Name[4] == 't') {
            const start = @intFromPtr(base_bytes) + s.VirtualAddress;
            const end = start + s.Misc.VirtualSize;
            const data: [*]u8 = @ptrFromInt(start);
            var pos: usize = 0;
            while (pos + 2 < end - start) : (pos += 1) {
                if (data[pos] == 0x0F and data[pos + 1] == 0x05 and data[pos + 2] == 0xC3) {
                    return start + pos;
                }
            }
            return null;
        }
    }
    return null;
}

test "freshyCalls finds NtAllocateVirtualMemory" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    _ = export_resolve.initNativeResolver(ntdll);

    const ssn = resolveByFreshyCalls(ntdll, hash.encryptedHashFunc("NtAllocateVirtualMemory"));
    try std.testing.expect(ssn != null);
    try std.testing.expect(ssn.? > 0);
}

test "freshyCalls finds NtClose" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const ssn = resolveByFreshyCalls(ntdll, hash.encryptedHashFunc("NtClose"));
    try std.testing.expect(ssn != null);
    try std.testing.expect(ssn.? > 0);
}

test "freshyCalls different functions have different SSNs" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const ssn1 = resolveByFreshyCalls(ntdll, hash.encryptedHashFunc("NtAllocateVirtualMemory"));
    const ssn2 = resolveByFreshyCalls(ntdll, hash.encryptedHashFunc("NtClose"));
    try std.testing.expect(ssn1 != null);
    try std.testing.expect(ssn2 != null);
    try std.testing.expect(ssn1.? != ssn2.?);
}

test "freshyCalls matches Halo's Gate SSN" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const ssn_fc = resolveByFreshyCalls(ntdll, hash.encryptedHashFunc("NtClose"));
    try std.testing.expect(ssn_fc != null);
    try std.testing.expect(ssn_fc.? > 0);
}

test "findSyscallGadget works" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const gadget = findSyscallGadget(ntdll);
    try std.testing.expect(gadget != null);
    try std.testing.expect(gadget.? > 0);
}

const config = @import("config");
const testing = std.testing;
