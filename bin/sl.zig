const std = @import("std");
const voidbox = @import("voidbox");
const builtin = @import("builtin");

const VERSION = "0.1.0";

fn getPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]const u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    // Print prompt
    try stdout.writeAll(prompt);

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

    // Simple argument parsing (avoiding std.process.args issues in 0.15.2)
    // For now, use hardcoded test
    const use_test_mode = true;

    // Get command-line arguments (when needed)
    //var args = std.ArrayList([]const u8).initCapacity(allocator, 0) catch unreachable;
    //defer args.deinit();

    if (use_test_mode) {
        // Test mode: hardcoded connection
        std.debug.print("sl - SSH/QUIC CLI tool (version {s})\n", .{VERSION});
        std.debug.print("Running in test mode...\n\n", .{});
        try runShellCommand(allocator, &[_][]const u8{"127.0.0.1"});
        return;
    }

    // Normal mode (when args parsing works)
    const args_items = &[_][]const u8{}; // TODO: Parse real args
    if (args_items.len == 0) {
        try printHelp();
        return;
    }

    const command = args_items[0];
    const command_args = if (args_items.len > 1) args_items[1..] else &[_][]const u8{};

    if (std.mem.eql(u8, command, "shell")) {
        try runShellCommand(allocator, command_args);
    } else if (std.mem.eql(u8, command, "sftp")) {
        try runSftpCommand(allocator, command_args);
    } else if (std.mem.eql(u8, command, "exec")) {
        try runExecCommand(allocator, command_args);
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "-v") or std.mem.eql(u8, command, "--version")) {
        try printVersion();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "--help")) {
        try printHelp();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        std.debug.print("Run 'sl help' for usage information\n", .{});
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
        \\    shell [user@]host[:port]    Connect to SSH server (interactive shell)
        \\    exec [user@]host command    Execute remote command
        \\    sftp [user@]host[:port]     SFTP file operations
        \\    version                     Show version information
        \\    help                        Show this help message
        \\
        \\OPTIONS:
        \\    -h, --help                  Show help
        \\    -v, --version               Show version
        \\    -p, --password <pass>       Use password authentication
        \\    -i, --identity <key>        Use public key authentication
        \\
        \\EXAMPLES:
        \\    sl shell user@example.com
        \\    sl shell user@example.com:2222
        \\    sl exec user@host "ls -la"
        \\    sl sftp user@example.com
        \\
        \\SFTP SUBCOMMANDS:
        \\    ls <path>                   List directory
        \\    get <remote> [local]        Download file
        \\    put <local> [remote]        Upload file
        \\    mkdir <path>                Create directory
        \\    rm <path>                   Remove file
        \\    rmdir <path>                Remove directory
        \\
        \\Run 'sl <command> --help' for more information on a specific command.
        \\
    , .{});
}

fn runShellCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl shell [user@]host[:port]\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];

    // Parse [user@]host[:port]
    var username: []const u8 = "root"; // Default username
    var hostname: []const u8 = undefined;
    var port: u16 = 2222; // SSH/QUIC default

    // Check for user@ prefix
    if (std.mem.indexOf(u8, host_arg, "@")) |at_pos| {
        username = host_arg[0..at_pos];
        hostname = host_arg[at_pos + 1 ..];
    } else {
        hostname = host_arg;
    }

    // Check for :port suffix
    if (std.mem.indexOf(u8, hostname, ":")) |colon_pos| {
        port = std.fmt.parseInt(u16, hostname[colon_pos + 1 ..], 10) catch {
            std.debug.print("Error: Invalid port number\n", .{});
            std.process.exit(1);
        };
        hostname = hostname[0..colon_pos];
    }

    std.debug.print("Connecting to {s}:{d} as {s}...\n", .{ hostname, port, username });

    // Initialize random number generator
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Create connection
    var conn = voidbox.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.debug.print("\nTroubleshooting:\n", .{});
        std.debug.print("  • Is the server running on {s}:{d}?\n", .{ hostname, port });
        std.debug.print("  • Does the server support SSH/QUIC protocol?\n", .{});
        std.debug.print("  • Check firewall/network connectivity\n", .{});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ SSH/QUIC connection established\n", .{});

    // Authenticate (try password for now)
    std.debug.print("Authenticating as {s}...\n", .{username});
    const password = try getPassword(allocator, "Password: ");
    defer allocator.free(password);

    const auth_success = conn.authenticatePassword(username, password) catch |err| {
        std.debug.print("✗ Authentication failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (!auth_success) {
        std.debug.print("✗ Authentication failed: Invalid credentials\n", .{});
        std.process.exit(1);
    }

    std.debug.print("✓ Authenticated successfully\n\n", .{});

    // Open shell session
    std.debug.print("Starting shell session...\n", .{});
    var session = conn.requestShell() catch |err| {
        std.debug.print("✗ Failed to start shell: {}\n", .{err});
        std.process.exit(1);
    };
    defer session.close() catch {};

    std.debug.print("✓ Shell session started\n", .{});
    std.debug.print("\n[Interactive shell would run here]\n", .{});
    std.debug.print("Note: Full terminal I/O not yet implemented\n", .{});
    std.debug.print("      Press Ctrl+C to exit\n\n", .{});

    // TODO: Implement terminal I/O loop
    // For now, just demonstrate the connection works
    std.debug.print("Session is active. Stack trace:\n", .{});
    std.debug.print("  1. UDP key exchange ✓\n", .{});
    std.debug.print("  2. QUIC connection ✓\n", .{});
    std.debug.print("  3. SSH authentication ✓\n", .{});
    std.debug.print("  4. Channel open ✓\n", .{});
    std.debug.print("  5. Shell request ✓\n", .{});
}

fn runExecCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        std.debug.print("Error: Host and command required\n", .{});
        std.debug.print("Usage: sl exec [user@]host[:port] <command>\n", .{});
        std.debug.print("Example: sl exec user@host \"ls -la\"\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];
    const command = args[1];

    // Parse [user@]host[:port]
    var username: []const u8 = "root";
    var hostname: []const u8 = undefined;
    var port: u16 = 2222;

    if (std.mem.indexOf(u8, host_arg, "@")) |at_pos| {
        username = host_arg[0..at_pos];
        hostname = host_arg[at_pos + 1 ..];
    } else {
        hostname = host_arg;
    }

    if (std.mem.indexOf(u8, hostname, ":")) |colon_pos| {
        port = std.fmt.parseInt(u16, hostname[colon_pos + 1 ..], 10) catch {
            std.debug.print("Error: Invalid port number\n", .{});
            std.process.exit(1);
        };
        hostname = hostname[0..colon_pos];
    }

    std.debug.print("Executing command on {s}:{d}...\n", .{ hostname, port });

    // Initialize random
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Connect
    var conn = voidbox.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

    // Authenticate
    const password = try getPassword(allocator, "Password: ");
    defer allocator.free(password);
    const auth_success = conn.authenticatePassword(username, password) catch |err| {
        std.debug.print("✗ Authentication failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (!auth_success) {
        std.debug.print("✗ Authentication failed\n", .{});
        std.process.exit(1);
    }

    // Execute command
    var session = conn.requestExec(command) catch |err| {
        std.debug.print("✗ Failed to execute command: {}\n", .{err});
        std.process.exit(1);
    };
    defer session.close() catch {};

    std.debug.print("✓ Command sent\n\n", .{});

    // Read output
    std.debug.print("--- Output ---\n", .{});
    const output = session.receiveData() catch |err| {
        std.debug.print("✗ Failed to read output: {}\n", .{err});
        return;
    };
    defer allocator.free(output);

    std.debug.print("{s}", .{output});
    std.debug.print("\n--- End Output ---\n", .{});
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl sftp [user@]host[:port]\n", .{});
        std.debug.print("\nSFTP Commands:\n", .{});
        std.debug.print("  ls <path>              List directory\n", .{});
        std.debug.print("  get <remote> [local]   Download file\n", .{});
        std.debug.print("  put <local> [remote]   Upload file\n", .{});
        std.debug.print("  mkdir <path>           Create directory\n", .{});
        std.debug.print("  rm <path>              Remove file\n", .{});
        std.debug.print("  rmdir <path>           Remove directory\n", .{});
        std.debug.print("  pwd                    Print working directory\n", .{});
        std.debug.print("  exit                   Exit SFTP session\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];

    // Parse [user@]host[:port]
    var username: []const u8 = "root";
    var hostname: []const u8 = undefined;
    var port: u16 = 2222;

    if (std.mem.indexOf(u8, host_arg, "@")) |at_pos| {
        username = host_arg[0..at_pos];
        hostname = host_arg[at_pos + 1 ..];
    } else {
        hostname = host_arg;
    }

    if (std.mem.indexOf(u8, hostname, ":")) |colon_pos| {
        port = std.fmt.parseInt(u16, hostname[colon_pos + 1 ..], 10) catch {
            std.debug.print("Error: Invalid port number\n", .{});
            std.process.exit(1);
        };
        hostname = hostname[0..colon_pos];
    }

    std.debug.print("Connecting to {s}:{d} for SFTP...\n", .{ hostname, port });

    // Initialize random
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Connect
    var conn = voidbox.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ Connected\n", .{});

    // Authenticate
    std.debug.print("Authenticating...\n", .{});
    const password = try getPassword(allocator, "Password: ");
    defer allocator.free(password);
    const auth_success = conn.authenticatePassword(username, password) catch |err| {
        std.debug.print("✗ Authentication failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (!auth_success) {
        std.debug.print("✗ Authentication failed\n", .{});
        std.process.exit(1);
    }

    std.debug.print("✓ Authenticated\n", .{});

    // Open SFTP channel
    std.debug.print("Starting SFTP subsystem...\n", .{});
    var sftp_channel = conn.openSftp() catch |err| {
        std.debug.print("✗ Failed to start SFTP: {}\n", .{err});
        std.process.exit(1);
    };
    defer sftp_channel.deinit();

    // Initialize SFTP client
    var sftp_client = voidbox.sftp.SftpClient.init(allocator, sftp_channel) catch |err| {
        std.debug.print("✗ Failed to initialize SFTP client: {}\n", .{err});
        std.process.exit(1);
    };
    defer sftp_client.deinit();

    std.debug.print("✓ SFTP session ready\n\n", .{});

    // Interactive SFTP shell
    try runSftpInteractive(allocator, &sftp_client);
}

fn runSftpInteractive(allocator: std.mem.Allocator, client: *voidbox.sftp.SftpClient) !void {
    std.debug.print("SFTP> ", .{});
    std.debug.print("[Interactive SFTP not yet implemented]\n", .{});
    std.debug.print("\nDemonstrating SFTP capabilities:\n", .{});
    std.debug.print("  • Connection: ✓\n", .{});
    std.debug.print("  • Authentication: ✓\n", .{});
    std.debug.print("  • SFTP subsystem: ✓\n", .{});
    std.debug.print("  • Protocol negotiation: ✓\n", .{});
    std.debug.print("\nAvailable operations:\n", .{});
    std.debug.print("  • open/close files\n", .{});
    std.debug.print("  • read/write data\n", .{});
    std.debug.print("  • list directories\n", .{});
    std.debug.print("  • create/remove directories\n", .{});
    std.debug.print("  • get file attributes\n", .{});
    std.debug.print("  • rename/remove files\n", .{});
    std.debug.print("\nTODO: Implement interactive command loop\n", .{});

    _ = allocator;
    _ = client;
}
