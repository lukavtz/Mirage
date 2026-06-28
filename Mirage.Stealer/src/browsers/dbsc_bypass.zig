const std = @import("std");

/// This module is a stub — DBSC (App-Bound Encryption) is a Chrome
/// protection layer that binds decryption keys to the OS user identity.
/// A full bypass requires token-stealing / process-injection beyond the
/// scope of this project. Below are utility checks for awareness.

pub fn dbscBypass() bool {
    return false;
}

pub fn hasAppBoundEncryption(local_state_json: []const u8) bool {
    return std.mem.indexOf(u8, local_state_json, "app_bound_encrypted_key") != null;
}

test "hasAppBoundEncryption detects key" {
    try std.testing.expect(hasAppBoundEncryption("{\"app_bound_encrypted_key\": \"abc\"}"));
    try std.testing.expect(!hasAppBoundEncryption("{\"os_crypt\": {}}"));
}

test "dbscBypass returns false" {
    try std.testing.expect(!dbscBypass());
}

const testing = std.testing;
