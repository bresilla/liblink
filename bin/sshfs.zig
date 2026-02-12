const std = @import("std");
const sshfs = @import("../lib/sshfs/filesystem.zig");

/// SSHFS Command-line Tool
///
/// Mount remote directories over SSH using FUSE.

const usage =
    \\Usage: sshfs [user@]host:[remote_path] <mount_point> [options]
    \\
    \\Options:
    \\  -p PORT          SSH port (default: 22)
    \\  -i KEYFILE       Private key file for authentication
    \\  -o allow_other   Allow other users to access mount
    \\  -o allow_root    Allow root to access mount
    \\  -d               Enable debug output
    \\  -f               Run in foreground
    \\  --cache-ttl N    Cache TTL in seconds (default: 5)
    \\  -h, --help       Show this help message
    \\
    \\Examples:
    \\  # Mount with password authentication
    \\  sshfs user@example.com:/remote/path /mnt/local
    \\
    \\  # Mount with SSH key
    \\  sshfs -i ~/.ssh/id_ed25519 user@example.com:/home /mnt/home
    \\
    \\  # Mount with custom port
    \\  sshfs -p 2222 user@example.com:/data /mnt/data
    \\
    \\  # Mount with debug output
    \\  sshfs -d user@example.com:/tmp /mnt/tmp
    \\
    \\To unmount:
    \\  fusermount -u /mnt/local
    \\
;

const Config = struct {
    hostname: []const u8,
    username: []const u8,
    port: u16 = 22,
    remote_path: []const u8 = "/",
    mount_point: []const u8,
    keyfile: ?[]const u8 = null,
    allow_other: bool = false,
    allow_root: bool = false,
    debug: bool = false,
    foreground: bool = true,
    cache_ttl: u64 = 5,
};

fn parseHostString(allocator: std.mem.Allocator, host_str: []const u8) !struct {
    username: []const u8,
    hostname: []const u8,
    path: []const u8,
} {
    // Parse [user@]host:[path]
    var username: []const u8 = "root";
    var hostname: []const u8 = undefined;
    var path: []const u8 = "/";

    // Split by '@' for username
    if (std.mem.indexOf(u8, host_str, "@")) |at_pos| {
        username = host_str[0..at_pos];
        const rest = host_str[at_pos + 1..];

        // Split by ':' for path
        if (std.mem.indexOf(u8, rest, ":")) |colon_pos| {
            hostname = rest[0..colon_pos];
            path = rest[colon_pos + 1..];
        } else {
            hostname = rest;
        }
    } else {
        // No username, split by ':'
        if (std.mem.indexOf(u8, host_str, ":")) |colon_pos| {
            hostname = host_str[0..colon_pos];
            path = host_str[colon_pos + 1..];
        } else {
            hostname = host_str;
        }
    }

    return .{
        .username = try allocator.dupe(u8, username),
        .hostname = try allocator.dupe(u8, hostname),
        .path = try allocator.dupe(u8, path),
    };
}

fn parseArgs(allocator: std.mem.Allocator) !Config {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // Skip program name

    var config: Config = undefined;
    var host_str: ?[]const u8 = null;
    var mount_point: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse return error.MissingPortValue;
            config.port = try std.fmt.parseInt(u16, port_str, 10);
        } else if (std.mem.eql(u8, arg, "-i")) {
            config.keyfile = args.next() orelse return error.MissingKeyfile;
        } else if (std.mem.eql(u8, arg, "-o")) {
            const opt = args.next() orelse return error.MissingOption;
            if (std.mem.eql(u8, opt, "allow_other")) {
                config.allow_other = true;
            } else if (std.mem.eql(u8, opt, "allow_root")) {
                config.allow_root = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{opt});
                return error.UnknownOption;
            }
        } else if (std.mem.eql(u8, arg, "-d")) {
            config.debug = true;
        } else if (std.mem.eql(u8, arg, "-f")) {
            config.foreground = true;
        } else if (std.mem.eql(u8, arg, "--cache-ttl")) {
            const ttl_str = args.next() orelse return error.MissingCacheTTL;
            config.cache_ttl = try std.fmt.parseInt(u64, ttl_str, 10);
        } else if (arg[0] == '-') {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        } else {
            // Positional arguments
            if (host_str == null) {
                host_str = try allocator.dupe(u8, arg);
            } else if (mount_point == null) {
                mount_point = try allocator.dupe(u8, arg);
            } else {
                std.debug.print("Too many arguments\n", .{});
                return error.TooManyArguments;
            }
        }
    }

    // Validate required arguments
    if (host_str == null) {
        std.debug.print("Error: Missing host argument\n\n{s}", .{usage});
        return error.MissingHost;
    }

    if (mount_point == null) {
        std.debug.print("Error: Missing mount point\n\n{s}", .{usage});
        return error.MissingMountPoint;
    }

    // Parse host string
    const parsed = try parseHostString(allocator, host_str.?);
    config.username = parsed.username;
    config.hostname = parsed.hostname;
    config.remote_path = parsed.path;
    config.mount_point = mount_point.?;

    return config;
}

fn getPassword(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    try stdout.writeAll("Password: ");

    // TODO: Disable echo for password input
    // For now, just read the line

    var buf: [256]u8 = undefined;
    const bytes_read = try stdin.read(&buf);
    const password = std.mem.trim(u8, buf[0..bytes_read], &std.ascii.whitespace);

    return try allocator.dupe(u8, password);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parseArgs(allocator) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        return err;
    };

    std.debug.print("SSHFS: Mounting {s}@{s}:{s} on {s}\n", .{
        config.username,
        config.hostname,
        config.remote_path,
        config.mount_point,
    });

    // Mount options
    const opts = sshfs.SshFilesystem.Options{
        .cache_ttl = config.cache_ttl,
        .remote_root = config.remote_path,
        .allow_other = config.allow_other,
        .allow_root = config.allow_root,
        .debug = config.debug,
    };

    // Mount with appropriate authentication
    if (config.keyfile) |keyfile| {
        // Public key authentication
        std.debug.print("Using SSH key: {s}\n", .{keyfile});
        try sshfs.mountWithKey(
            allocator,
            config.hostname,
            config.port,
            config.username,
            keyfile,
            config.remote_path,
            config.mount_point,
            opts,
        );
    } else {
        // Password authentication
        const password = try getPassword(allocator);
        defer allocator.free(password);

        try sshfs.mount(
            allocator,
            config.hostname,
            config.port,
            config.username,
            password,
            config.remote_path,
            config.mount_point,
            opts,
        );
    }

    std.debug.print("Filesystem mounted successfully!\n", .{});
    std.debug.print("To unmount: fusermount -u {s}\n", .{config.mount_point});
}
