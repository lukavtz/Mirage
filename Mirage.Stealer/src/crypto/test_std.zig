const std = @import("std");
const testing = std.testing;

test "std.crypto.aes_gcm" {
    const aead = std.crypto.aead.aes_gcm.Aes256Gcm;
    try testing.expect(aead.key_length == 32);
    try testing.expect(aead.nonce_length == 12);
}

test "std.crypto.chacha20" {
    const C = std.crypto.stream.chacha.ChaCha20IETF;
    try testing.expect(C.key_length == 32);
}

test "std.crypto.pbkdf2" {
    var key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&key, "password", "saltysalt", 1, std.crypto.auth.hmac.HmacSha1);
}

test "std.crypto.poly1305" {
    const mac = std.crypto.onetimeauth.Poly1305;
    try testing.expect(mac.mac_length == 16);
}
