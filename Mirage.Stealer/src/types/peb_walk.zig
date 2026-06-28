const std = @import("std");
const config = @import("config");
const types = @import("types.zig");

pub fn getModuleByHash(moduleHash: u32) ?types.PVOID {
    const peb = getPeb();
    const ldr = peb.Ldr;
    const head = &ldr.InMemoryOrderModuleList;
    var current = head.Flink;

    while (current != head) : (current = current.Flink) {
        const entry_ptr = @intFromPtr(current) - 0x10;
        const entry = @as(*types.LDR_DATA_TABLE_ENTRY, @ptrFromInt(entry_ptr));
        const name_buf = entry.BaseDllName.Buffer;
        const name_len = entry.BaseDllName.Length / 2;

        var h: u32 = config.SEED;
        for (0..name_len) |i| {
            var c: u8 = @as(u8, @truncate(name_buf[i]));
            if (c >= 'A' and c <= 'Z') c += 32;
            for (0..28) |_| {
                h = std.math.rotl(u32, h, 5);
                h = h ^ c;
                h = h *% 0x1B873593 +% 0x85EBCA6B;
            }
        }

        if (h == moduleHash) {
            return entry.DllBase;
        }
    }
    return null;
}

pub inline fn getPeb() *types.PEB {
    return asm volatile ("mov %%gs:0x60, %[ret]"
        : [ret] "=r" (-> *types.PEB),
    );
}
