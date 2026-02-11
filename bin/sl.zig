const std = @import("std");
const voidbox = @import("voidbox");

const VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printHelp();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        try printVersion();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try printHelp();
    } else if (std.mem.eql(u8, command, "sftp")) {
        try runSftpCommand(allocator, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n\n", .{command});
        try printHelp();
        std.process.exit(1);
    }
}

fn printVersion() !void {
    std.debug.print("sl version {s}\n", .{VERSION});
    std.debug.print("SSH/QUIC implementation with SFTP support\n", .{});
}

fn printHelp() !void {
    std.debug.print(
        \\sl - SSH/QUIC CLI tool
        \\
        \\USAGE:
        \\    sl <command> [options]
        \\
        \\COMMANDS:
        \\    sftp <subcommand>     SFTP file operations
        \\    version               Show version information
        \\    help                  Show this help message
        \\
        \\SFTP SUBCOMMANDS:
        \\    get <remote> <local>  Download a file
        \\    put <local> <remote>  Upload a file
        \\    ls [path]             List directory contents
        \\    mkdir <path>          Create a directory
        \\    rmdir <path>          Remove a directory
        \\    rm <path>             Remove a file
        \\    mv <old> <new>        Rename/move a file or directory
        \\    stat <path>           Show file attributes
        \\
        \\OPTIONS:
        \\    -h, --help            Show help
        \\    -v, --version         Show version
        \\
        \\EXAMPLES:
        \\    sl sftp get /remote/file.txt ./local.txt
        \\    sl sftp put ./local.txt /remote/file.txt
        \\    sl sftp ls /remote/directory
        \\    sl sftp mkdir /remote/newdir
        \\
    , .{});
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: SFTP subcommand required\n\n", .{});
        try printHelp();
        std.process.exit(1);
    }

    const subcommand = args[0];
    const subargs = if (args.len > 1) args[1..] else &[_][]const u8{};

    if (std.mem.eql(u8, subcommand, "get")) {
        try sftpGet(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "put")) {
        try sftpPut(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "ls")) {
        try sftpLs(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "mkdir")) {
        try sftpMkdir(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "rmdir")) {
        try sftpRmdir(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "rm")) {
        try sftpRm(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "mv")) {
        try sftpMv(allocator, subargs);
    } else if (std.mem.eql(u8, subcommand, "stat")) {
        try sftpStat(allocator, subargs);
    } else {
        std.debug.print("Unknown SFTP subcommand: {s}\n\n", .{subcommand});
        try printHelp();
        std.process.exit(1);
    }
}

// SFTP command implementations (placeholders for now)

fn sftpGet(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'get' requires remote and local paths\n", .{});
        std.debug.print("Usage: sl sftpget <remote> <local>\n", .{});
        std.process.exit(1);
    }

    const remote_path = args[0];
    const local_path = args[1];

    std.debug.print("TODO: Download {s} to {s}\n", .{ remote_path, local_path });
}

fn sftpPut(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'put' requires local and remote paths\n", .{});
        std.debug.print("Usage: sl sftpput <local> <remote>\n", .{});
        std.process.exit(1);
    }

    const local_path = args[0];
    const remote_path = args[1];

    std.debug.print("TODO: Upload {s} to {s}\n", .{ local_path, remote_path });
}

fn sftpLs(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    const path = if (args.len > 0) args[0] else ".";

    std.debug.print("TODO: List directory {s}\n", .{path});
}

fn sftpMkdir(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'mkdir' requires a path\n", .{});
        std.debug.print("Usage: sl sftpmkdir <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Create directory {s}\n", .{path});
}

fn sftpRmdir(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'rmdir' requires a path\n", .{});
        std.debug.print("Usage: sl sftprmdir <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Remove directory {s}\n", .{path});
}

fn sftpRm(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'rm' requires a path\n", .{});
        std.debug.print("Usage: sl sftprm <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Remove file {s}\n", .{path});
}

fn sftpMv(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'mv' requires old and new paths\n", .{});
        std.debug.print("Usage: sl sftpmv <old> <new>\n", .{});
        std.process.exit(1);
    }

    const old_path = args[0];
    const new_path = args[1];

    std.debug.print("TODO: Rename {s} to {s}\n", .{ old_path, new_path });
}

fn sftpStat(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'stat' requires a path\n", .{});
        std.debug.print("Usage: sl sftpstat <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Show attributes for {s}\n", .{path});
}
