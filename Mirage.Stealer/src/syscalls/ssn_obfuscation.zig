const config = @import("config");

pub fn obfuscateSsn(ssn: u32) u32 {
    return ssn ^ config.SSN_XOR_KEY;
}

pub fn deobfuscateSsn(obfuscated: u32) u32 {
    return obfuscated ^ config.SSN_XOR_KEY;
}

test "obfuscateSsn roundtrip" {
    const ssn: u32 = 0x42;
    const enc = obfuscateSsn(ssn);
    const dec = deobfuscateSsn(enc);
    try std.testing.expectEqual(ssn, dec);
    try std.testing.expect(enc != ssn);
}

test "obfuscateSsn zero" {
    const enc = obfuscateSsn(0);
    try std.testing.expect(enc != 0);
    const dec = deobfuscateSsn(enc);
    try std.testing.expectEqual(@as(u32, 0), dec);
}

test "obfuscateSsn max" {
    const enc = obfuscateSsn(0xFFFF);
    const dec = deobfuscateSsn(enc);
    try std.testing.expectEqual(@as(u32, 0xFFFF), dec);
}

const testing = std.testing;
