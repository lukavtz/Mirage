const std = @import("std");
const types = @import("../types/types.zig");
const peb = @import("../types/peb.zig");

fn unlinkEntry(entry: *types.LIST_ENTRY) void {
    const flink = entry.Flink;
    const blink = entry.Blink;
    flink.Blink = blink;
    blink.Flink = flink;
    entry.Flink = entry;
    entry.Blink = entry;
}

pub fn unlinkModule(target_base: types.PVOID) bool {
    const peb_ptr = peb.getPeb();
    const ldr = peb_ptr.Ldr;

    const it = &ldr.InLoadOrderModuleList;
    var entry = it.Flink;
    while (@intFromPtr(entry) != @intFromPtr(it)) {
        const ldr_entry: *types.LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InLoadOrderLinks", entry);
        const next = entry.Flink;
        if (@intFromPtr(ldr_entry.DllBase) == @intFromPtr(target_base)) {
            unlinkEntry(&ldr_entry.InLoadOrderLinks);
            unlinkEntry(&ldr_entry.InMemoryOrderLinks);
            unlinkEntry(&ldr_entry.InInitializationOrderLinks);
            return true;
        }
        entry = next;
    }
    return false;
}
