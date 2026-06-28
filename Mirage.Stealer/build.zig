const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .msvc,
        },
    });

    const exe = b.addExecutable(.{
        .name = "Mirage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
            .strip = true,
            .single_threaded = true,
        }),
    });

    exe.root_module.addAnonymousImport("config", .{
        .root_source_file = b.path("src/config/config.zig"),
    });

    exe.root_module.addAnonymousImport("clipper_config", .{
        .root_source_file = b.path("src/clipper/config.zig"),
    });

    exe.subsystem = .Windows;
    b.installArtifact(exe);

    const test_step = b.step("test", "Run unit tests");
    const test_exe = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .Debug,
            .single_threaded = true,
        }),
    });
    test_exe.root_module.addAnonymousImport("config", .{
        .root_source_file = b.path("src/config/config.zig"),
    });
    test_exe.root_module.addAnonymousImport("clipper_config", .{
        .root_source_file = b.path("src/clipper/config.zig"),
    });
    const run = b.addRunArtifact(test_exe);
    test_step.dependOn(&run.step);
}
