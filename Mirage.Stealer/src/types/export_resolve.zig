const std = @import("std");
const types = @import("types.zig");
const hash = @import("hash.zig");
var g_ldr_get_procedure_address: ?*const fn (types.PVOID, [*]const u8, ?*types.PVOID) callconv(.winapi) types.NTSTATUS = null;

pub fn initNativeResolver(ntdll_base: types.PVOID) bool {
    const base_bytes = @as([*]const u8, @ptrCast(@alignCast(ntdll_base)));
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return false;

    const lfanew: usize = @intCast(dos.e_lfanew);
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(base_bytes + lfanew)));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return false;

    const export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (export_dir_rva == 0) return false;

    const export_dir = @as(*const types.IMAGE_EXPORT_DIRECTORY, @ptrCast(@alignCast(base_bytes + export_dir_rva)));
    const names_rva = export_dir.AddressOfNames;
    const funcs_rva = export_dir.AddressOfFunctions;
    const ords_rva = export_dir.AddressOfNameOrdinals;

    if (names_rva == 0 or funcs_rva == 0 or ords_rva == 0) return false;

    const num_names = export_dir.NumberOfNames;
    const names = @as([*]const u32, @ptrCast(@alignCast(base_bytes + names_rva)));
    const funcs = @as([*]const u32, @ptrCast(@alignCast(base_bytes + funcs_rva)));
    const ords = @as([*]const u16, @ptrCast(@alignCast(base_bytes + ords_rva)));

    const target_hash = hash.comptimeHashFunc("LdrGetProcedureAddress");

    for (0..num_names) |i| {
        const name_ptr = base_bytes + names[i];
        var name_len: usize = 0;
        while (name_ptr[name_len] != 0) : (name_len += 1) {}

        const name_slice = name_ptr[0..name_len];
        var h2: u32 = config.SEED;
        for (name_slice) |c| {
            for (0..27) |_| {
                h2 = std.math.rotl(u32, h2, 5);
                h2 = h2 ^ c;
                h2 = h2 *% 0x1B873593 +% 0x85EBCA6B;
            }
        }

        if (h2 == target_hash) {
            const ordinal = ords[i];
            const func_rva = funcs[ordinal];
            const LdrGetProcAddrFn = *const fn (types.PVOID, [*]const u8, ?*types.PVOID) callconv(.winapi) types.NTSTATUS;
            const func_ptr: LdrGetProcAddrFn = @ptrCast(@alignCast(base_bytes + func_rva));
            g_ldr_get_procedure_address = func_ptr;
            return true;
        }
    }
    return false;
}

const config = @import("config");

pub fn getFunctionByHash(module_base: types.PVOID, func_hash: u32) ?*const anyopaque {
    const base_bytes = @as([*]const u8, @ptrCast(@alignCast(module_base)));
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;

    const lfanew: usize = @intCast(dos.e_lfanew);
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(@alignCast(base_bytes + lfanew)));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (export_dir_rva == 0) return null;

    const export_dir = @as(*const types.IMAGE_EXPORT_DIRECTORY, @ptrCast(@alignCast(base_bytes + export_dir_rva)));
    const names_rva = export_dir.AddressOfNames;
    const funcs_rva = export_dir.AddressOfFunctions;
    const ords_rva = export_dir.AddressOfNameOrdinals;

    if (names_rva == 0 or funcs_rva == 0 or ords_rva == 0) return null;

    const num_names = export_dir.NumberOfNames;
    const names = @as([*]const u32, @ptrCast(@alignCast(base_bytes + names_rva)));
    const funcs = @as([*]const u32, @ptrCast(@alignCast(base_bytes + funcs_rva)));
    const ords = @as([*]const u16, @ptrCast(@alignCast(base_bytes + ords_rva)));

    for (0..num_names) |i| {
        const name_ptr = base_bytes + names[i];
        var name_len: usize = 0;
        while (name_ptr[name_len] != 0) : (name_len += 1) {}

        var h: u32 = config.SEED;
        for (name_ptr[0..name_len]) |c| {
            for (0..27) |_| {
                h = std.math.rotl(u32, h, 5);
                h = h ^ c;
                h = h *% 0x1B873593 +% 0x85EBCA6B;
            }
        }

        if (h == func_hash) {
            const ordinal = ords[i];
            const func_rva = funcs[ordinal];
            return @ptrCast(@alignCast(base_bytes + func_rva));
        }
    }
    return null;
}
