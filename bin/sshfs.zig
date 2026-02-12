const std = @import("std");
const voidbox = @import("voidbox");
const sshfs = voidbox.sshfs.filesystem;
const keyfile = @import("voidbox").auth.keyfile;

/// SSHFS Command-line Tool
///
/// Mount remote directories over SSH using FUSE.

// ANSI color codes
const Color = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const magenta = "\x1b[35m";
    const cyan = "\x1b[36m";
    const white = "\x1b[37m";
    const gray = "\x1b[90m";

    const bold_green = "\x1b[1;32m";
    const bold_red = "\x1b[1;31m";
    const bold_yellow = "\x1b[1;33m";
    const bold_blue = "\x1b[1;34m";
    const bold_cyan = "\x1b[1;36m";
    const bold_magenta = "\x1b[1;35m";
};

fn printUsage() void {
    const c = Color;

    // Header
    std.debug.print("{s}sshfs{s} - Mount remote directories over SSH using FUSE\n\n", .{ c.bold_cyan, c.reset });

    // Usage
    std.debug.print("{s}USAGE:{s}\n", .{ c.bold_yellow, c.reset });
    std.debug.print("    {s}sshfs{s} [user@]host:[remote_path] <mount_point> [options]\n\n", .{ c.cyan, c.reset });

    // Options
    std.debug.print("{s}OPTIONS:{s}\n", .{ c.bold_yellow, c.reset });
    std.debug.print("    {s}-p{s} PORT          SSH port (default: 22)\n", .{ c.green, c.reset });
    std.debug.print("    {s}-i{s} KEYFILE       Private key file for authentication\n", .{ c.green, c.reset });
    std.debug.print("    {s}-o{s} allow_other   Allow other users to access mount\n", .{ c.green, c.reset });
    std.debug.print("    {s}-o{s} allow_root    Allow root to access mount\n", .{ c.green, c.reset });
    std.debug.print("    {s}-d{s}               Enable debug output\n", .{ c.green, c.reset });
    std.debug.print("    {s}-f{s}               Run in foreground\n", .{ c.green, c.reset });
    std.debug.print("    {s}--cache-ttl{s} N    Cache TTL in seconds (default: 5)\n", .{ c.green, c.reset });
    std.debug.print("    {s}-h, --help{s}       Show this help message\n\n", .{ c.green, c.reset });

    // Examples
    std.debug.print("{s}EXAMPLES:{s}\n", .{ c.bold_yellow, c.reset });
    std.debug.print("    {s}# Mount with password authentication{s}\n", .{ c.gray, c.reset });
    std.debug.print("    {s}sshfs user@example.com:/remote/path /mnt/local{s}\n\n", .{ c.cyan, c.reset });
    std.debug.print("    {s}# Mount with SSH key{s}\n", .{ c.gray, c.reset });
    std.debug.print("    {s}sshfs -i ~/.ssh/id_ed25519 user@example.com:/home /mnt/home{s}\n\n", .{ c.cyan, c.reset });
    std.debug.print("    {s}# Mount with custom port{s}\n", .{ c.gray, c.reset });
    std.debug.print("    {s}sshfs -p 2222 user@example.com:/data /mnt/data{s}\n\n", .{ c.cyan, c.reset });
    std.debug.print("    {s}# Mount with debug output{s}\n", .{ c.gray, c.reset });
    std.debug.print("    {s}sshfs -d user@example.com:/tmp /mnt/tmp{s}\n\n", .{ c.cyan, c.reset });

    // Unmount
    std.debug.print("{s}UNMOUNT:{s}\n", .{ c.bold_yellow, c.reset });
    std.debug.print("    {s}fusermount -u /mnt/local{s}\n", .{ c.cyan, c.reset });
}

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
            printUsage();
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
            std.debug.print("{s}Error:{s} Unknown option: {s}\n\n", .{ Color.bold_red, Color.reset, arg });
            printUsage();
            return error.UnknownOption;
        } else {
            // Positional arguments
            if (host_str == null) {
                host_str = try allocator.dupe(u8, arg);
            } else if (mount_point == null) {
                mount_point = try allocator.dupe(u8, arg);
            } else {
                std.debug.print("{s}Error:{s} Too many arguments\n\n", .{ Color.bold_red, Color.reset });
                printUsage();
                return error.TooManyArguments;
            }
        }
    }

    // Validate required arguments
    if (host_str == null) {
        std.debug.print("{s}Error:{s} Missing host argument\n\n", .{ Color.bold_red, Color.reset });
        printUsage();
        return error.MissingHost;
    }

    if (mount_point == null) {
        std.debug.print("{s}Error:{s} Missing mount point\n\n", .{ Color.bold_red, Color.reset });
        printUsage();
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

fn mountWithPublicKey(
    allocator: std.mem.Allocator,
    config: Config,
    opts: sshfs.SshFilesystem.Options,
    parsed_key: *const keyfile.ParsedKey,
) !void {
    // Create SSH connection
    const random = std.crypto.random;
    var conn = try voidbox.connection.connectClient(
        allocator,
        config.hostname,
        config.port,
        random,
    );
    defer conn.deinit();

    std.debug.print("{s}✓{s} SSH/QUIC connection established\n", .{ Color.bold_green, Color.reset });

    // Authenticate with public key
    std.debug.print("{s}[AUTH]{s} Authenticating as {s}{s}{s} with {s}...\n", .{
        Color.bold_blue,
        Color.reset,
        Color.cyan,
        config.username,
        Color.reset,
        parsed_key.algorithm_name,
    });

    // Validate key sizes for Ed25519
    if (parsed_key.key_type == .ed25519) {
        if (parsed_key.private_key.len != 64) {
            std.debug.print("{s}Error:{s} Invalid Ed25519 private key size: {} bytes (expected 64)\n", .{
                Color.bold_red,
                Color.reset,
                parsed_key.private_key.len,
            });
            return error.InvalidKeySize;
        }
    }

    const auth_success = try conn.authenticatePublicKey(
        config.username,
        parsed_key.algorithm_name,
        parsed_key.public_key,
        parsed_key.private_key[0..64],
    );

    if (!auth_success) {
        std.debug.print("{s}Error:{s} Authentication failed\n", .{ Color.bold_red, Color.reset });
        return error.AuthenticationFailed;
    }

    std.debug.print("{s}✓{s} Authentication successful\n", .{ Color.bold_green, Color.reset });

    // Create filesystem
    var fs = try sshfs.SshFilesystem.init(allocator, &conn, config.mount_point, opts);
    defer fs.deinit();

    std.debug.print("{s}✓{s} Filesystem mounted successfully!\n", .{ Color.bold_green, Color.reset });
    std.debug.print("{s}→{s} To unmount: {s}fusermount -u {s}{s}\n", .{
        Color.blue,
        Color.reset,
        Color.cyan,
        config.mount_point,
        Color.reset,
    });

    // Mount (this will block until unmounted)
    try fs.mount(opts);
}

fn getPassword(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    // Print prompt
    try stdout.writeAll("Password: ");

    // Disable echo using termios
    const c = @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    });

    var old_termios: c.termios = undefined;
    var new_termios: c.termios = undefined;

    // Get current terminal settings
    if (c.tcgetattr(stdin.handle, &old_termios) != 0) {
        return error.TermiosGetFailed;
    }

    // Copy settings and disable echo
    new_termios = old_termios;
    new_termios.c_lflag &= ~@as(c_uint, c.ECHO);

    // Apply new settings
    if (c.tcsetattr(stdin.handle, c.TCSANOW, &new_termios) != 0) {
        return error.TermiosSetFailed;
    }

    // Ensure we restore terminal settings
    defer {
        _ = c.tcsetattr(stdin.handle, c.TCSANOW, &old_termios);
        stdout.writeAll("\n") catch {};
    }

    // Read password
    var buffer: [256]u8 = undefined;
    const bytes_read = try stdin.read(&buffer);

    if (bytes_read == 0) {
        return error.NoPasswordProvided;
    }

    // Find newline
    const line = if (std.mem.indexOfScalar(u8, buffer[0..bytes_read], '\n')) |idx|
        buffer[0..idx]
    else
        buffer[0..bytes_read];

    // Trim any trailing whitespace/newlines
    const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

    if (trimmed.len == 0) {
        return error.EmptyPassword;
    }

    // Allocate and return password
    return try allocator.dupe(u8, trimmed);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parseArgs(allocator) catch |err| {
        std.debug.print("{s}Error:{s} Failed to parse arguments: {any}\n", .{ Color.bold_red, Color.reset, err });
        return err;
    };

    std.debug.print("{s}[SSHFS]{s} Mounting {s}{s}@{s}:{s}{s} on {s}{s}{s}\n", .{
        Color.bold_blue,
        Color.reset,
        Color.cyan,
        config.username,
        config.hostname,
        config.remote_path,
        Color.reset,
        Color.green,
        config.mount_point,
        Color.reset,
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
    if (config.keyfile) |keyfile_path| {
        // Public key authentication
        std.debug.print("{s}[AUTH]{s} Using key file: {s}{s}{s}\n", .{
            Color.bold_blue,
            Color.reset,
            Color.cyan,
            keyfile_path,
            Color.reset,
        });

        var parsed_key = keyfile.parsePrivateKeyFile(allocator, keyfile_path) catch |err| {
            std.debug.print("{s}Error:{s} Failed to parse key file: {any}\n", .{ Color.bold_red, Color.reset, err });
            return err;
        };
        defer parsed_key.deinit();

        try mountWithPublicKey(
            allocator,
            config,
            opts,
            &parsed_key,
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

    std.debug.print("{s}✓{s} Filesystem mounted successfully!\n", .{ Color.bold_green, Color.reset });
    std.debug.print("{s}→{s} To unmount: {s}fusermount -u {s}{s}\n", .{ Color.blue, Color.reset, Color.cyan, config.mount_point, Color.reset });
}
