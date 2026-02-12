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

    std.debug.print("✓ Shell session started\n\n", .{});
    std.debug.print("Interactive shell session active. Type commands and press Enter.\n", .{});
    std.debug.print("Press Ctrl+D or type 'exit' to close the session.\n\n", .{});

    // Run interactive shell I/O loop
    try runShellInteractive(allocator, &session);
}

fn runShellInteractive(allocator: std.mem.Allocator, session: *voidbox.channels.SessionChannel) !void {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    // Simple line-based I/O loop
    // Note: A production implementation would use raw terminal mode
    // and handle character-by-character I/O with proper terminal control
    while (true) {
        // Read line from stdin
        var line_buffer: [4096]u8 = undefined;
        var byte_buffer: [1]u8 = undefined;
        var line_len: usize = 0;

        // Read until newline or EOF
        while (true) {
            const n = stdin.read(&byte_buffer) catch |err| {
                if (err == error.EOF or err == error.EndOfStream) return;
                return err;
            };
            if (n == 0) return; // EOF
            if (byte_buffer[0] == '\n') break;
            if (line_len >= line_buffer.len) return error.LineTooLong;
            line_buffer[line_len] = byte_buffer[0];
            line_len += 1;
        }

        const line = line_buffer[0..line_len];

        // Check for exit command
        if (std.mem.eql(u8, std.mem.trim(u8, line, &std.ascii.whitespace), "exit")) {
            break;
        }

        // Append newline for the remote shell
        var command_buffer: [4097]u8 = undefined;
        @memcpy(command_buffer[0..line.len], line);
        command_buffer[line.len] = '\n';
        const command_with_newline = command_buffer[0 .. line.len + 1];

        // Send command to remote shell
        try session.sendData(command_with_newline);

        // Receive response
        // Note: This is simplified - a real implementation would handle
        // partial reads, escape sequences, and asynchronous output
        const response = session.receiveData() catch |err| {
            var err_buf: [256]u8 = undefined;
            const err_msg = try std.fmt.bufPrint(&err_buf, "Error receiving data: {}\n", .{err});
            try stdout.writeAll(err_msg);
            continue;
        };
        defer allocator.free(response);

        // Write response to stdout
        try stdout.writeAll(response);
    }

    try stdout.writeAll("\nClosing shell session...\n");
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
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    var current_dir = std.ArrayList(u8).init(allocator);
    defer current_dir.deinit();
    try current_dir.appendSlice("/");

    while (true) {
        // Print prompt
        try stdout.writeAll("sftp> ");

        // Read command line
        var line_buffer: [1024]u8 = undefined;
        var line_len: usize = 0;

        // Read until newline or EOF
        var byte_buffer: [1]u8 = undefined;
        while (true) {
            const n = stdin.read(&byte_buffer) catch |err| {
                if (err == error.EOF or err == error.EndOfStream) return;
                return err;
            };
            if (n == 0) return; // EOF
            if (byte_buffer[0] == '\n') break;
            if (line_len >= line_buffer.len) continue; // Skip if line too long
            line_buffer[line_len] = byte_buffer[0];
            line_len += 1;
        }

        const line = line_buffer[0..line_len];
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

        if (trimmed.len == 0) continue;

        // Parse command and arguments
        var iter = std.mem.splitScalar(u8, trimmed, ' ');
        const command = iter.next() orelse continue;

        // Handle commands
        if (std.mem.eql(u8, command, "exit") or std.mem.eql(u8, command, "quit")) {
            break;
        } else if (std.mem.eql(u8, command, "pwd")) {
            try stdout.writeAll(current_dir.items);
            try stdout.writeAll("\n");
        } else if (std.mem.eql(u8, command, "ls")) {
            const path = iter.next() orelse current_dir.items;
            try sftpListDirectory(allocator, client, path);
        } else if (std.mem.eql(u8, command, "cd")) {
            const path = iter.next() orelse {
                try stdout.writeAll("Error: path required\n");
                continue;
            };
            // Update current directory (simplified - doesn't resolve paths)
            current_dir.clearRetainingCapacity();
            if (path[0] == '/') {
                try current_dir.appendSlice(path);
            } else {
                try current_dir.appendSlice(current_dir.items);
                if (current_dir.items[current_dir.items.len - 1] != '/') {
                    try current_dir.append('/');
                }
                try current_dir.appendSlice(path);
            }
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
                \\  ls [path]              List directory
                \\  cd <path>              Change directory
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

fn sftpListDirectory(allocator: std.mem.Allocator, client: *voidbox.sftp.SftpClient, path: []const u8) !void {
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
        for (entries) |entry| {
            allocator.free(entry.filename);
            allocator.free(entry.longname);
        }
        allocator.free(entries);
    }

    for (entries) |entry| {
        try stdout.writeAll(entry.filename);
        try stdout.writeAll("\n");
    }
}

fn sftpDownloadFile(allocator: std.mem.Allocator, client: *voidbox.sftp.SftpClient, remote_path: []const u8, local_path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const handle = client.open(remote_path, .read, .{}) catch |err| {
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

fn sftpUploadFile(allocator: std.mem.Allocator, client: *voidbox.sftp.SftpClient, local_path: []const u8, remote_path: []const u8) !void {
    _ = allocator; // Currently unused but may be needed for future enhancements
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    const local_file = std.fs.cwd().openFile(local_path, .{}) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error opening local file: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    defer local_file.close();

    const handle = client.open(remote_path, .write, .{ .create = true, .truncate = true }) catch |err| {
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

fn sftpMkdir(client: *voidbox.sftp.SftpClient, path: []const u8) !void {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    client.mkdir(path, .{}) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Error creating directory: {}\n", .{err});
        try stdout.writeAll(msg);
        return;
    };
    try stdout.writeAll("Directory created: ");
    try stdout.writeAll(path);
    try stdout.writeAll("\n");
}

fn sftpRemove(client: *voidbox.sftp.SftpClient, path: []const u8) !void {
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
