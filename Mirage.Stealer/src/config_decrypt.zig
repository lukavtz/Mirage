const std = @import("std");
const aes_gcm_bcrypt = @import("crypto/aes_gcm_bcrypt.zig");

const CONFIG_SIG = "MIRAGECFG";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub fn decryptConfig(image_base: usize, allocator: std.mem.Allocator) ?[]u8 {
    const sig_bytes = CONFIG_SIG;
    var offset: usize = 0;

    while (offset < 1024 * 1024) {
        const ptr = @as([*]const u8, @ptrFromInt(image_base + offset));
        var match = true;
        for (sig_bytes, 0..) |c, j| {
            if (ptr[j] != c) { match = false; break; }
        }
        if (match) {
            const data = @as([*]const u8, @ptrFromInt(image_base + offset + sig_bytes.len))[0..1024];
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
    const tag = data[KEY_SIZE + NONCE_SIZE..][0..TAG_SIZE];
    const ciphertext = data[KEY_SIZE + NONCE_SIZE + TAG_SIZE..];

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
