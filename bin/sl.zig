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
    } else if (std.mem.eql(u8, command, "shell")) {
        try runShellCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "sftp")) {
        try runSftpCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "daemon")) {
        try runDaemonCommand(allocator, args[2..]);
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
        \\    shell [user@]host     Connect to SSH server (interactive shell)
        \\    sftp [user@]host      SFTP file operations (see 'sl sftp --help')
        \\    daemon                Run as background daemon
        \\    version               Show version information
        \\    help                  Show this help message
        \\
        \\OPTIONS:
        \\    -h, --help            Show help
        \\    -v, --version         Show version
        \\
        \\EXAMPLES:
        \\    sl shell user@example.com
        \\    sl sftp user@example.com
        \\    sl sftp --help
        \\
        \\Run 'sl <command> --help' for more information on a specific command.
        \\
    , .{});
}

fn printSftpHelp() !void {
    std.debug.print(
        \\sl sftp - SFTP file transfer operations
        \\
        \\USAGE:
        \\    sl sftp [user@]host <subcommand> [options]
        \\
        \\SUBCOMMANDS:
        \\    get <remote> <local>  Download a file
        \\    put <local> <remote>  Upload a file
        \\    ls [path]             List directory contents
        \\    mkdir <path>          Create a directory
        \\    rmdir <path>          Remove a directory
        \\    rm <path>             Remove a file
        \\    mv <old> <new>        Rename/move a file or directory
        \\    stat <path>           Show file attributes
        \\
        \\EXAMPLES:
        \\    sl sftp user@example.com get /remote/file.txt ./local.txt
        \\    sl sftp user@example.com put ./local.txt /remote/file.txt
        \\    sl sftp user@example.com ls /remote/directory
        \\    sl sftp user@example.com mkdir /remote/newdir
        \\
    , .{});
}

fn runShellCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;

    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl shell [user@]host\n", .{});
        std.process.exit(1);
    }

    const host = args[0];
    std.debug.print("TODO: Connect to {s} and open interactive shell\n", .{host});
}

fn runDaemonCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    _ = args;
    std.debug.print("TODO: Run as background daemon\n", .{});
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    // Check for --help first
    if (args.len > 0 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h"))) {
        try printSftpHelp();
        return;
    }

    if (args.len < 2) {
        std.debug.print("Error: Host and subcommand required\n\n", .{});
        try printSftpHelp();
        std.process.exit(1);
    }

    const host = args[0];
    const subcommand = args[1];
    const subargs = if (args.len > 2) args[2..] else &[_][]const u8{};

    if (std.mem.eql(u8, subcommand, "get")) {
        try sftpGet(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "put")) {
        try sftpPut(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "ls")) {
        try sftpLs(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "mkdir")) {
        try sftpMkdir(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "rmdir")) {
        try sftpRmdir(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "rm")) {
        try sftpRm(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "mv")) {
        try sftpMv(allocator, host, subargs);
    } else if (std.mem.eql(u8, subcommand, "stat")) {
        try sftpStat(allocator, host, subargs);
    } else {
        std.debug.print("Unknown SFTP subcommand: {s}\n\n", .{subcommand});
        try printSftpHelp();
        std.process.exit(1);
    }
}

// SFTP command implementations (placeholders for now)

fn sftpGet(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'get' requires remote and local paths\n", .{});
        std.debug.print("Usage: sl sftp [user@]host get <remote> <local>\n", .{});
        std.process.exit(1);
    }

    const remote_path = args[0];
    const local_path = args[1];

    std.debug.print("TODO: Connect to {s} and download {s} to {s}\n", .{ host, remote_path, local_path });
}

fn sftpPut(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'put' requires local and remote paths\n", .{});
        std.debug.print("Usage: sl sftp [user@]host put <local> <remote>\n", .{});
        std.process.exit(1);
    }

    const local_path = args[0];
    const remote_path = args[1];

    std.debug.print("TODO: Connect to {s} and upload {s} to {s}\n", .{ host, local_path, remote_path });
}

fn sftpLs(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    const path = if (args.len > 0) args[0] else ".";

    std.debug.print("TODO: Connect to {s} and list directory {s}\n", .{ host, path });
}

fn sftpMkdir(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'mkdir' requires a path\n", .{});
        std.debug.print("Usage: sl sftp [user@]host mkdir <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Connect to {s} and create directory {s}\n", .{ host, path });
}

fn sftpRmdir(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'rmdir' requires a path\n", .{});
        std.debug.print("Usage: sl sftp [user@]host rmdir <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Connect to {s} and remove directory {s}\n", .{ host, path });
}

fn sftpRm(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'rm' requires a path\n", .{});
        std.debug.print("Usage: sl sftp [user@]host rm <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Connect to {s} and remove file {s}\n", .{ host, path });
}

fn sftpMv(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 2) {
        std.debug.print("Error: 'mv' requires old and new paths\n", .{});
        std.debug.print("Usage: sl sftp [user@]host mv <old> <new>\n", .{});
        std.process.exit(1);
    }

    const old_path = args[0];
    const new_path = args[1];

    std.debug.print("TODO: Connect to {s} and rename {s} to {s}\n", .{ host, old_path, new_path });
}

fn sftpStat(allocator: std.mem.Allocator, host: []const u8, args: []const []const u8) !void {
    _ = allocator;
    if (args.len < 1) {
        std.debug.print("Error: 'stat' requires a path\n", .{});
        std.debug.print("Usage: sl sftp [user@]host stat <path>\n", .{});
        std.process.exit(1);
    }

    const path = args[0];
    std.debug.print("TODO: Connect to {s} and show attributes for {s}\n", .{ host, path });
}
