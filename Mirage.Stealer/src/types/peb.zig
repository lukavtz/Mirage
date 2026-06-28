const std = @import("std");
const types = @import("types.zig");

pub inline fn getPeb() *types.PEB {
    return asm volatile ("mov %%gs:0x60, %[ret]"
        : [ret] "=r" (-> *types.PEB),
    );
}
