const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");

pub const POOL_SIZE: usize = 64;
const POOL_MASK: usize = POOL_SIZE - 1;

pub export var gadget_pool: [POOL_SIZE]usize = undefined;
pub export var gadget_pool_len: u32 = 0;

const TextBounds = struct { start: usize, end: usize };

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
            return TextBounds{ .start = @intFromPtr(bp) + s.VirtualAddress, .end = @intFromPtr(bp) + s.VirtualAddress + s.Misc.VirtualSize };
        }
    }
    return null;
}

fn scanModule(base: types.PVOID, pool: []usize) usize {
    const bounds = getTextSectionBounds(base) orelse return 0;
    const data: [*]u8 = @ptrFromInt(bounds.start);
    const len = bounds.end - bounds.start;
    var count: usize = 0;
    var pos: usize = 0;
    while (pos + 2 < len and count < pool.len) : (pos += 1) {
        if (data[pos] == 0x0F and data[pos + 1] == 0x05 and data[pos + 2] == 0xC3) {
            pool[count] = bounds.start + pos;
            count += 1;
        }
    }
    return count;
}

pub fn initialize() bool {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return false;
    const n = scanModule(ntdll, gadget_pool[0..]);
    gadget_pool_len = @intCast(n);
    if (gadget_pool_len > 0 and gadget_pool_len < POOL_SIZE) {
        var i: usize = gadget_pool_len;
        while (i < POOL_SIZE) : (i += 1) {
            gadget_pool[i] = gadget_pool[i % gadget_pool_len];
        }
    }
    if (gadget_pool_len == 0) return false;
    gadget_pool_len = POOL_SIZE;
    return true;
}
