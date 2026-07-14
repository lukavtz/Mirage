const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
    });

    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    // Supported cross-compilation targets
    const supported_targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
    };

    // ── Main build (default / user-specified target) ──
    {
        const e = b.addExecutable(.{
            .name = "Mirage",
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .strip = true, .single_threaded = true }),
        });
        if (target.result.os.tag == .windows) {
            e.subsystem = .Windows;
        }
        e.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        e.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        b.installArtifact(e);
    }

    // ── Cross-compilation targets ──
    const cross_step = b.step("cross", "Build for all supported targets");
    for (&supported_targets) |q| {
        const t = b.resolveTargetQuery(q);
        const e = b.addExecutable(.{
            .name = if (q.os_tag == .windows) "Mirage" else b.fmt("Mirage-{s}", .{@tagName(q.os_tag.?)}),
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = t, .optimize = .ReleaseSmall, .strip = true, .single_threaded = true }),
        });
        if (q.os_tag == .windows) {
            e.subsystem = .Windows;
        }
        e.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        e.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        cross_step.dependOn(&b.addInstallArtifact(e, .{}).step);
    }

    // ── Integration Test (only for default target) ──
    {
        const e = b.addExecutable(.{
            .name = "MirageIntegrationTest",
            .root_module = b.createModule(.{ .root_source_file = b.path("src/integration_test.zig"), .target = target, .optimize = optimize, .single_threaded = true }),
        });
        e.subsystem = .Console;
        e.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        b.installArtifact(e);
    }

    // ── Unit Tests ──
    const test_step = b.step("test", "Run unit tests");
    {
        const t = b.addTest(.{
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = .Debug, .single_threaded = true }),
        });
        t.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        t.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // ── Platform module tests ──
    const plat_test_step = b.step("test-platform", "Run platform layer tests");
    {
        const t = b.addTest(.{
            .root_module = b.createModule(.{ .root_source_file = b.path("src/platform_test_runner.zig"), .target = target, .optimize = .Debug, .single_threaded = true }),
        });
        t.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        t.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        plat_test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // ─── Cross-compile tests ───
    const cross_test_step = b.step("test-cross", "Run tests on all supported targets");
    for (&supported_targets) |q| {
        const t = b.resolveTargetQuery(q);
        const test_exe = b.addTest(.{
            .root_module = b.createModule(.{ .root_source_file = b.path("src/platform_test_runner.zig"), .target = t, .optimize = .Debug, .single_threaded = true }),
        });
        test_exe.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        test_exe.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        const run_cmd = b.addRunArtifact(test_exe);
        run_cmd.skip_foreign_checks = true;
        cross_test_step.dependOn(&run_cmd.step);
    }
}
