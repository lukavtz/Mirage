const std = @import("std");

pub fn secureZero(ptr: anytype, len: usize) void {
    const bytes = @as([*]volatile u8, @ptrCast(@alignCast(ptr)))[0..len];
    for (bytes) |*b| b.* = 0;
}

pub fn readU32Le(ptr: [*]const u8) u32 {
    return @as(u32, ptr[0]) |
        (@as(u32, ptr[1]) << 8) |
        (@as(u32, ptr[2]) << 16) |
        (@as(u32, ptr[3]) << 24);
}

pub fn trimmedLen(buf: []const u8) usize {
    var i: usize = buf.len;
    while (i > 0 and buf[i - 1] == 0) : (i -= 1) {}
    return i;
}
