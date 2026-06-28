const types = @import("../types/types.zig");
const engine = @import("engine.zig");

var console_handle: types.HANDLE = undefined;
var have_console: bool = false;
var initialized: bool = false;

fn ensureConsole() bool {
    if (initialized) return have_console;
    initialized = true;

    const conout_chars = [_]u16{ 0x5C, 0x3F, 0x3F, 0x5C, 0x43, 0x4F, 0x4E, 0x4F, 0x55, 0x54, 0x24, 0x00 };

    var name_ustr = types.UNICODE_STRING{
        .Length = 22,
        .MaximumLength = 24,
        .Buffer = @constCast(@ptrCast(conout_chars[0..].ptr)),
    };

    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_ustr,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var iosb: types.IO_STATUS_BLOCK = undefined;
    var h: types.HANDLE = undefined;

    const status = engine.NtCreateFile(
        &h,
        types.FILE_GENERIC_WRITE,
        @ptrCast(&oa),
        @ptrCast(&iosb),
        null,
        0,
        types.FILE_SHARE_READ | types.FILE_SHARE_WRITE,
        types.FILE_OPEN,
        types.FILE_NON_DIRECTORY_FILE | types.FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );

    if (status >= 0) {
        console_handle = h;
        have_console = true;
        return true;
    }
    return false;
}

pub fn print(msg: []const u8) void {
    if (!ensureConsole()) return;
    var iosb: types.IO_STATUS_BLOCK = undefined;
    _ = engine.NtWriteFile(
        console_handle,
        @as(types.HANDLE, @ptrFromInt(1)),
        null,
        null,
        @ptrCast(&iosb),
        @ptrCast(@constCast(msg.ptr)),
        @as(types.ULONG, @intCast(msg.len)),
        null,
        null,
    );
}

const hex_chars = "0123456789abcdef";

pub fn printHex(val: usize) void {
    if (val == 0) return print("0x0");
    var buf: [18]u8 = undefined;
    var idx: usize = 17;
    var v = val;
    while (true) {
        buf[idx] = hex_chars[v & 0xF];
        v >>= 4;
        if (v == 0) break;
        idx -= 1;
    }
    idx -= 1;
    buf[idx] = 'x';
    buf[idx - 1] = '0';
    print(buf[(idx - 1)..18]);
}
