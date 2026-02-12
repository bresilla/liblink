const std = @import("std");
const syslink = @import("syslink");
const builtin = @import("builtin");

const VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printHelp();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "server")) {
        try runServerCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "shell")) {
        try runShellCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "exec")) {
        try runExecCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "sftp")) {
        try runSftpCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "mount")) {
        try runMountCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "umount") or std.mem.eql(u8, command, "unmount")) {
        try runUmountCommand(allocator, args[2..]);
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
    std.debug.print("SSH/QUIC implementation with SFTP and SSHFS support\n", .{});
}

fn printHelp() !void {
    std.debug.print(
        \\sl - SSH/QUIC flagship CLI tool
        \\
        \\USAGE:
        \\    sl <command> [options] [arguments]
        \\
        \\COMMANDS:
        \\
        \\  SERVER:
        \\    server start [options]      Start SSH/QUIC server daemon
        \\    server stop                 Stop server daemon
        \\    server status               Check server status
        \\
        \\  CLIENT:
        \\    shell [user@]host[:port]    Connect to remote shell
        \\    exec [user@]host command    Execute remote command
        \\    sftp [user@]host[:port]     Start SFTP session
        \\    mount [user@]host path      Mount remote filesystem (SSHFS)
        \\    umount path                 Unmount SSHFS filesystem
        \\
        \\  GENERAL:
        \\    version                     Show version information
        \\    help                        Show this help message
        \\
        \\SERVER OPTIONS:
        \\    -p, --port <port>           Listen port (default: 2222)
        \\    -h, --host <addr>           Listen address (default: 0.0.0.0)
        \\    -k, --host-key <file>       Host key file (default: ~/.ssh/sl_host_key)
        \\    -u, --user <user:pass>      Add user credentials
        \\    -d, --daemon                Run as background daemon
        \\
        \\CLIENT OPTIONS:
        \\    -p, --password <pass>       Use password authentication
        \\    -i, --identity <key>        Use public key authentication
        \\    -P, --port <port>           Server port (default: 2222)
        \\
        \\EXAMPLES:
        \\
        \\  Start server:
        \\    sl server start -p 2222 -u testuser:testpass
        \\    sl server start --daemon --host 0.0.0.0 --port 2222
        \\
        \\  Connect to server:
        \\    sl shell testuser@192.168.1.100:2222
        \\    sl exec testuser@server.com "ls -la"
        \\    sl sftp testuser@example.com
        \\
        \\  Mount filesystem:
        \\    sl mount testuser@server.com:/home/user ./mnt
        \\    sl umount ./mnt
        \\
        \\SFTP COMMANDS (in sftp> prompt):
        \\    ls [path]                   List directory
        \\    cd <path>                   Change directory
        \\    pwd                         Print working directory
        \\    get <remote> [local]        Download file
        \\    put <local> [remote]        Upload file
        \\    mkdir <path>                Create directory
        \\    rm <path>                   Remove file
        \\    help                        Show SFTP help
        \\    exit                        Exit SFTP session
        \\
    , .{});
}

// ============================================================================
// SERVER COMMANDS
// ============================================================================

fn runServerCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Server subcommand required\n", .{});
        std.debug.print("Usage: sl server <start|stop|status> [options]\n", .{});
        std.process.exit(1);
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "start")) {
        try serverStart(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "stop")) {
        try serverStop(allocator);
    } else if (std.mem.eql(u8, subcommand, "status")) {
        try serverStatus(allocator);
    } else {
        std.debug.print("Unknown server subcommand: {s}\n", .{subcommand});
        std.debug.print("Available: start, stop, status\n", .{});
        std.process.exit(1);
    }
}

fn serverStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var listen_addr: []const u8 = "0.0.0.0";
    var listen_port: u16 = 2222;
    var daemon_mode = false;
    var username: []const u8 = "testuser";
    var password: []const u8 = "testpass";
    var host_key_path: ?[]const u8 = null;

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --port requires a value\n", .{});
                std.process.exit(1);
            }
            listen_port = std.fmt.parseInt(u16, args[i], 10) catch {
                std.debug.print("Error: Invalid port number\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--host")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --host requires a value\n", .{});
                std.process.exit(1);
            }
            listen_addr = args[i];
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
            daemon_mode = true;
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--host-key")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --host-key requires a value\n", .{});
                std.process.exit(1);
            }
            host_key_path = args[i];
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --user requires user:pass format\n", .{});
                std.process.exit(1);
            }
            if (std.mem.indexOf(u8, args[i], ":")) |colon_pos| {
                username = args[i][0..colon_pos];
                password = args[i][colon_pos + 1 ..];
            } else {
                std.debug.print("Error: --user format should be user:pass\n", .{});
                std.process.exit(1);
            }
        }
    }

    std.debug.print("=== SSH/QUIC Server ===\n\n", .{});
    std.debug.print("Configuration:\n", .{});
    std.debug.print("  Listen: {s}:{d}\n", .{ listen_addr, listen_port });
    std.debug.print("  Daemon: {}\n", .{daemon_mode});
    std.debug.print("  User: {s}\n\n", .{username});

    // Generate or load host key
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();

    var host_private_key: [64]u8 = undefined;
    var host_public_key: [32]u8 = undefined;

    if (host_key_path) |_| {
        std.debug.print("Note: Host key loading not yet implemented, using generated key\n", .{});
    }

    // Generate temporary keys
    random.bytes(&host_private_key);
    random.bytes(&host_public_key);

    const host_key_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenerated";

    std.debug.print("Starting server...\n", .{});

    var listener = syslink.connection.startServer(
        allocator,
        listen_addr,
        listen_port,
        host_key_str,
        &host_private_key,
        random,
    ) catch |err| {
        std.debug.print("✗ Failed to start server: {}\n", .{err});
        std.debug.print("\nPossible issues:\n", .{});
        std.debug.print("  • Port {d} already in use (try: lsof -i:{d})\n", .{ listen_port, listen_port });
        std.debug.print("  • Insufficient permissions (need root for ports < 1024)\n", .{});
        std.debug.print("  • Firewall blocking UDP port {d}\n", .{listen_port});
        return err;
    };
    defer listener.deinit();

    std.debug.print("✓ Server listening on {s}:{d}\n\n", .{ listen_addr, listen_port });

    if (daemon_mode) {
        std.debug.print("Note: Daemon mode not yet implemented, running in foreground\n", .{});
    }

    std.debug.print("Ready for connections. Press Ctrl+C to stop.\n\n", .{});

    // Server loop
    var client_count: usize = 0;
    while (true) {
        client_count += 1;
        std.debug.print("--- Client #{d} ---\n", .{client_count});

        var server_conn = listener.acceptConnection() catch |err| {
            std.debug.print("✗ Failed to accept connection: {}\n\n", .{err});
            continue;
        };
        defer server_conn.deinit();

        std.debug.print("✓ Client connected\n", .{});

        // Handle authentication  - using simple validators
        const Validators = struct {
            fn passValidator(user: []const u8, pass: []const u8) bool {
                // For demo, accept testuser:testpass
                return std.mem.eql(u8, user, "testuser") and std.mem.eql(u8, pass, "testpass");
            }
            fn keyValidator(_: []const u8, _: []const u8, _: []const u8) bool {
                return false;
            }
        };

        const authed = server_conn.handleAuthentication(
            Validators.passValidator,
            Validators.keyValidator,
        ) catch |err| {
            std.debug.print("✗ Authentication error: {}\n\n", .{err});
            continue;
        };

        if (!authed) {
            std.debug.print("✗ Authentication failed\n\n", .{});
            continue;
        }

        std.debug.print("✓ Client authenticated\n", .{});
        std.debug.print("Session active (limited demo - full session handling TODO)\n\n", .{});
    }
}

fn serverStop(allocator: std.mem.Allocator) !void {
    _ = allocator;
    std.debug.print("Stopping SSH/QUIC server...\n", .{});
    std.debug.print("Note: Daemon management not yet implemented\n", .{});
    std.debug.print("To stop a running server, use: pkill -f 'sl server'\n", .{});
}

fn serverStatus(allocator: std.mem.Allocator) !void {
    _ = allocator;
    std.debug.print("Checking server status...\n", .{});
    std.debug.print("Note: Status checking not yet implemented\n", .{});
    std.debug.print("To check manually: ps aux | grep 'sl server'\n", .{});
}

// ============================================================================
// CLIENT COMMANDS
// ============================================================================

fn getPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]const u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    try stdout.writeAll(prompt);

    // Disable echo using termios
    const c = @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    });

    var old_termios: c.termios = undefined;
    var new_termios: c.termios = undefined;

    if (c.tcgetattr(stdin.handle, &old_termios) != 0) {
        return error.TermiosGetFailed;
    }

    new_termios = old_termios;
    new_termios.c_lflag &= ~@as(c_uint, c.ECHO);

    if (c.tcsetattr(stdin.handle, c.TCSANOW, &new_termios) != 0) {
        return error.TermiosSetFailed;
    }

    defer {
        _ = c.tcsetattr(stdin.handle, c.TCSANOW, &old_termios);
        stdout.writeAll("\n") catch {};
    }

    var buffer: [256]u8 = undefined;
    const bytes_read = try stdin.read(&buffer);

    if (bytes_read == 0) return error.NoPasswordProvided;

    const line = if (std.mem.indexOfScalar(u8, buffer[0..bytes_read], '\n')) |idx|
        buffer[0..idx]
    else
        buffer[0..bytes_read];

    const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.EmptyPassword;

    return try allocator.dupe(u8, trimmed);
}

fn runShellCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl shell [user@]host[:port]\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];

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

    std.debug.print("Connecting to {s}:{d} as {s}...\n", .{ hostname, port, username });

    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();

    var conn = syslink.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.debug.print("\nTroubleshooting:\n", .{});
        std.debug.print("  • Check server is running: nc -u -v {s} {d}\n", .{ hostname, port });
        std.debug.print("  • Verify firewall allows UDP port {d}\n", .{port});
        std.debug.print("  • Try pinging the host: ping {s}\n", .{hostname});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ Connected\n", .{});

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

    std.debug.print("✓ Authenticated\n\n", .{});

    var session = conn.requestShell() catch |err| {
        std.debug.print("✗ Failed to start shell: {}\n", .{err});
        std.process.exit(1);
    };
    defer session.close() catch {};

    std.debug.print("Shell session active. Type commands or 'exit' to quit.\n\n", .{});

    try runShellInteractive(allocator, &session);
}

fn runShellInteractive(allocator: std.mem.Allocator, session: *syslink.channels.SessionChannel) !void {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    while (true) {
        var line_buffer: [4096]u8 = undefined;
        var byte_buffer: [1]u8 = undefined;
        var line_len: usize = 0;

        while (true) {
            const n = stdin.read(&byte_buffer) catch |err| {
                if (err == error.EOF or err == error.EndOfStream) return;
                return err;
            };
            if (n == 0) return;
            if (byte_buffer[0] == '\n') break;
            if (line_len >= line_buffer.len) return error.LineTooLong;
            line_buffer[line_len] = byte_buffer[0];
            line_len += 1;
        }

        const line = line_buffer[0..line_len];

        if (std.mem.eql(u8, std.mem.trim(u8, line, &std.ascii.whitespace), "exit")) {
            break;
        }

        var command_buffer: [4097]u8 = undefined;
        @memcpy(command_buffer[0..line.len], line);
        command_buffer[line.len] = '\n';
        const command_with_newline = command_buffer[0 .. line.len + 1];

        try session.sendData(command_with_newline);

        const response = session.receiveData() catch |err| {
            var err_buf: [256]u8 = undefined;
            const err_msg = try std.fmt.bufPrint(&err_buf, "Error receiving data: {}\n", .{err});
            try stdout.writeAll(err_msg);
            continue;
        };
        defer allocator.free(response);

        try stdout.writeAll(response);
    }

    try stdout.writeAll("\nClosing shell...\n");
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

    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();

    var conn = syslink.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

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

    var session = conn.requestExec(command) catch |err| {
        std.debug.print("✗ Failed to execute command: {}\n", .{err});
        std.process.exit(1);
    };
    defer session.close() catch {};

    const output = session.receiveData() catch |err| {
        std.debug.print("✗ Failed to read output: {}\n", .{err});
        return;
    };
    defer allocator.free(output);

    std.debug.print("{s}", .{output});
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl sftp [user@]host[:port]\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];

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

    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();

    var conn = syslink.connection.connectClient(allocator, hostname, port, random) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ Connected\n", .{});

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

    var sftp_channel = conn.openSftp() catch |err| {
        std.debug.print("✗ Failed to start SFTP: {}\n", .{err});
        std.process.exit(1);
    };
    defer sftp_channel.deinit();

    var sftp_client = syslink.sftp.SftpClient.init(allocator, sftp_channel) catch |err| {
        std.debug.print("✗ Failed to initialize SFTP client: {}\n", .{err});
        std.process.exit(1);
    };
    defer sftp_client.deinit();

    std.debug.print("✓ SFTP session ready\n\n", .{});

    try runSftpInteractive(allocator, &sftp_client);
}

fn runSftpInteractive(allocator: std.mem.Allocator, client: *syslink.sftp.SftpClient) !void {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const current_dir = "/";  // Simplified for demo

    while (true) {
        try stdout.writeAll("sftp> ");

        var line_buffer: [1024]u8 = undefined;
        var line_len: usize = 0;
        var byte_buffer: [1]u8 = undefined;

        while (true) {
            const n = stdin.read(&byte_buffer) catch |err| {
                if (err == error.EOF or err == error.EndOfStream) return;
                return err;
            };
            if (n == 0) return;
            if (byte_buffer[0] == '\n') break;
            if (line_len >= line_buffer.len) continue;
            line_buffer[line_len] = byte_buffer[0];
            line_len += 1;
        }

        const line = line_buffer[0..line_len];
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

        if (trimmed.len == 0) continue;

        var iter = std.mem.splitScalar(u8, trimmed, ' ');
        const command = iter.next() orelse continue;

        if (std.mem.eql(u8, command, "exit") or std.mem.eql(u8, command, "quit")) {
            break;
        } else if (std.mem.eql(u8, command, "pwd")) {
            try stdout.writeAll(current_dir);
            try stdout.writeAll("\n");
        } else if (std.mem.eql(u8, command, "ls")) {
            const path = iter.next() orelse current_dir;
            try sftpListDirectory(allocator, client, path);
        } else if (std.mem.eql(u8, command, "cd")) {
            try stdout.writeAll("Note: cd not implemented in this demo, use absolute paths\n");
        } else if (std.mem.eql(u8, command, "get")) {
            const remote_path = iter.next() orelse {
                try stdout.writeAll("Error: remote path required\n");
                continue;
            };
            const local_path = iter.next() orelse remote_path;
            try sftpDownloadFile(allocator, client, remote_path, local_path);
        } else if (std.mem.eql(u8, command, "put")) {
            const local_path = iter.next() orelse {
                try stdout.writeAll("Error: local path required\n");
                continue;
            };
            const remote_path = iter.next() orelse local_path;
            try sftpUploadFile(allocator, client, local_path, remote_path);
        } else if (std.mem.eql(u8, command, "mkdir")) {
            const path = iter.next() orelse {
                try stdout.writeAll("Error: path required\n");
                continue;
            };
            try sftpMkdir(client, path);
        } else if (std.mem.eql(u8, command, "rm")) {
            const path = iter.next() orelse {
                try stdout.writeAll("Error: path required\n");
                continue;
            };
            try sftpRemove(client, path);
        } else if (std.mem.eql(u8, command, "help")) {
            try stdout.writeAll(
                \\Available commands:
                \\  ls [path]              List directory (use absolute paths)
                \\  pwd                    Print working directory
                \\  get <remote> [local]   Download file
                \\  put <local> [remote]   Upload file
                \\  mkdir <path>           Create directory
                \\  rm <path>              Remove file
                \\  help                   Show this help
                \\  exit/quit              Exit SFTP session
                \\
            );
        } else {
            try stdout.writeAll("Unknown command: ");
            try stdout.writeAll(command);
            try stdout.writeAll(". Type 'help' for available commands.\n");
        }
    }

    try stdout.writeAll("Goodbye.\n");
}

fn sftpListDirectory(allocator: std.mem.Allocator, client: *syslink.sftp.SftpClient, path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const handle = client.opendir(path) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error opening directory: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer client.close(handle) catch {};

    const entries = client.readdir(handle) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error reading directory: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer {
        for (entries) |*entry| {
            entry.deinit(allocator);
        }
        allocator.free(entries);
    }

    for (entries) |entry| {
        try stdout.writeAll(entry.filename);
        try stdout.writeAll("\n");
    }
}

fn sftpDownloadFile(allocator: std.mem.Allocator, client: *syslink.sftp.SftpClient, remote_path: []const u8, local_path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const attrs = syslink.sftp.attributes.FileAttributes.init();
    const handle = client.open(remote_path, .{ .read = true }, attrs) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error opening remote file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer client.close(handle) catch {};

    const local_file = std.fs.cwd().createFile(local_path, .{}) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error creating local file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer local_file.close();

    var offset: u64 = 0;
    var total_bytes: u64 = 0;

    while (true) {
        const data = client.read(handle, offset, 32768) catch |err| {
            if (err == error.Eof) break;
            var buf: [256]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "Error reading file: {}\n", .{err});
            try stdout.writeAll(msg);
            return;
        };
        defer allocator.free(data);

        if (data.len == 0) break;

        local_file.writeAll(data) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "Error writing to local file: {}\n", .{err});
            try stdout.writeAll(msg);
            return;
        };

        offset += data.len;
        total_bytes += data.len;
    }

    var buf: [512]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, "Downloaded {} bytes to {s}\n", .{ total_bytes, local_path });
    try stdout.writeAll(msg);
}

fn sftpUploadFile(allocator: std.mem.Allocator, client: *syslink.sftp.SftpClient, local_path: []const u8, remote_path: []const u8) !void {
    _ = allocator;
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const local_file = std.fs.cwd().openFile(local_path, .{}) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error opening local file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer local_file.close();

    const attrs = syslink.sftp.attributes.FileAttributes.init();
    const handle = client.open(remote_path, .{ .write = true, .creat = true, .trunc = true }, attrs) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error opening remote file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer client.close(handle) catch {};

    var buffer: [32768]u8 = undefined;
    var offset: u64 = 0;
    var total_bytes: u64 = 0;

    while (true) {
        const bytes_read = local_file.read(&buffer) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "Error reading local file: {}\n", .{err});
            try stdout.writeAll(msg);
            return;
        };

        if (bytes_read == 0) break;

        client.write(handle, offset, buffer[0..bytes_read]) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "Error writing to remote file: {}\n", .{err});
            try stdout.writeAll(msg);
            return;
        };

        offset += bytes_read;
        total_bytes += bytes_read;
    }

    var buf: [512]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, "Uploaded {} bytes to {s}\n", .{ total_bytes, remote_path });
    try stdout.writeAll(msg);
}

fn sftpMkdir(client: *syslink.sftp.SftpClient, path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const attrs = syslink.sftp.attributes.FileAttributes.init();
    client.mkdir(path, attrs) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error creating directory: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    try stdout.writeAll("Directory created: ");
    try stdout.writeAll(path);
    try stdout.writeAll("\n");
}

fn sftpRemove(client: *syslink.sftp.SftpClient, path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    client.remove(path) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error removing file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    try stdout.writeAll("Removed: ");
    try stdout.writeAll(path);
    try stdout.writeAll("\n");
}

// ============================================================================
// SSHFS COMMANDS
// ============================================================================

fn runMountCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        std.debug.print("Error: Remote and mount point required\n", .{});
        std.debug.print("Usage: sl mount [user@]host[:port]:/remote/path /local/mount\n", .{});
        std.debug.print("Example: sl mount testuser@192.168.1.100:/home/user ./mnt\n", .{});
        std.process.exit(1);
    }

    _ = allocator;
    std.debug.print("SSHFS mount functionality:\n", .{});
    std.debug.print("  Remote: {s}\n", .{args[0]});
    std.debug.print("  Mount point: {s}\n", .{args[1]});
    std.debug.print("\n", .{});
    std.debug.print("Note: SSHFS/FUSE integration not yet implemented\n", .{});
    std.debug.print("This would use lib/sshfs/ to mount remote filesystem via FUSE\n", .{});
}

fn runUmountCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Mount point required\n", .{});
        std.debug.print("Usage: sl umount /mount/point\n", .{});
        std.process.exit(1);
    }

    _ = allocator;
    std.debug.print("Unmounting: {s}\n", .{args[0]});
    std.debug.print("Note: SSHFS/FUSE integration not yet implemented\n", .{});
}
