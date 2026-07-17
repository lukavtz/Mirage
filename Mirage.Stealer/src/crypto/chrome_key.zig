const std = @import("std");
const testing = std.testing;

const BASE64_DECODE: [256]i8 = blk: {
    var table: [256]i8 = .{ -1 } ** 256;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (chars, 0..) |c, i| {
        table[c] = @as(i8, @intCast(i));
    }
    table['='] = 0;
    break :blk table;
};

pub fn base64Decode(input: []const u8, out: []u8) ?[]u8 {
    if (input.len == 0 or input.len % 4 != 0) return null;

    const max_out = (input.len / 4) * 3;
    if (out.len < max_out) return null;

    var padding: usize = 0;
    if (input.len >= 2 and input[input.len - 2] == '=') {
        padding = 2;
    } else if (input.len >= 1 and input[input.len - 1] == '=') {
        padding = 1;
    }

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
        if (c >= 0) {
            out[out_pos] = @as(u8, @intCast((b << 4) | (c >> 2)));
            out_pos += 1;
        }

        if (out_pos >= out_len) break;
        if (d >= 0) {
            out[out_pos] = @as(u8, @intCast((c << 6) | d));
            out_pos += 1;
        }
    }

    return out[0..out_len];
}

pub fn extractEncryptedKey(json: []const u8, out: []u8) ?[]u8 {
    const marker = "\"encrypted_key\":\"";
    const start = std.mem.indexOf(u8, json, marker) orelse return null;
    const value_start = start + marker.len;
    const end = std.mem.indexOfScalarPos(u8, json, value_start, '"') orelse return null;
    const b64 = json[value_start..end];
    return base64Decode(b64, out);
}

// ── Tests ──

test "base64Decode standard" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("SGVsbG8gV29ybGQ=", &buf) orelse return error.DecodeFailed;
    try testing.expectEqualSlices(u8, "Hello World", result);
}

test "base64Decode empty" {
    var buf: [4]u8 = undefined;
    const result = base64Decode("", &buf);
    try testing.expect(result == null);
}

test "base64Decode invalid length" {
    var buf: [4]u8 = undefined;
    try testing.expect(base64Decode("abc", &buf) == null);
    try testing.expect(base64Decode("abcde", &buf) == null);
}

test "base64Decode no padding" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("Zm9vYmFy", &buf) orelse return error.DecodeFailed;
    try testing.expectEqualSlices(u8, "foobar", result);
}

test "base64Decode with padding" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("Zm9v", &buf) orelse return error.DecodeFailed;
    try testing.expectEqualSlices(u8, "foo", result);
}

test "base64Decode double padding" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("QQ==", &buf) orelse return error.DecodeFailed;
    try testing.expectEqual(@as(usize, 1), result.len);
    try testing.expectEqual(@as(u8, 'A'), result[0]);
}

test "base64Decode binary output" {
    var buf: [64]u8 = undefined;
    const result = base64Decode("AAECAwQFBgcICQoLDA0ODw==", &buf) orelse return error.DecodeFailed;
    try testing.expect(result.len == 16);
    try testing.expect(result[0] == 0x00);
    try testing.expect(result[1] == 0x01);
    try testing.expect(result[15] == 0x0F);
}

test "extractEncryptedKey from Local State" {
    var buf: [256]u8 = undefined;
    const json =
        \\{"os_crypt":{"encrypted_key":"QUFBQkJCQ0NERERFRUVGRg=="}}
    ;
    const result = extractEncryptedKey(json, &buf) orelse return error.ExtractFailed;
    try testing.expectEqualSlices(u8, "AAABBBCCCDDDEEEF", result);
}

test "extractEncryptedKey missing key" {
    var buf: [64]u8 = undefined;
    try testing.expect(extractEncryptedKey("{}", &buf) == null);
    try testing.expect(extractEncryptedKey("{\"other\": 1}", &buf) == null);
}

test "extractEncryptedKey empty value" {
    var buf: [64]u8 = undefined;
    const json =
        \\{"os_crypt":{"encrypted_key":""}}
    ;
    try testing.expect(extractEncryptedKey(json, &buf) == null);
}

test "base64Decode output buffer too small" {
    var tiny: [2]u8 = undefined;
    try testing.expect(base64Decode("AAAA", &tiny) == null);
}
