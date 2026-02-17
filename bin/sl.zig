const std = @import("std");
const syslink = @import("syslink");
const builtin = @import("builtin");

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("signal.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
    @cInclude("string.h");
    @cInclude("sys/ioctl.h");
    @cInclude("termios.h");
    @cInclude("poll.h");
});

const VERSION = "0.0.4";

// Global flag for signal handling
var should_exit = std.atomic.Value(bool).init(false);

/// Signal handler for Ctrl+C
fn handleSigInt(sig: c_int) callconv(.c) void {
    _ = sig;
    should_exit.store(true, .release);
}

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
        \\
        \\  GENERAL:
        \\    version                     Show version information
        \\    help                        Show this help message
        \\
        \\SERVER OPTIONS:
        \\    -p, --port <port>           Listen port (default: 2222)
        \\    -h, --host <addr>           Listen address (default: 0.0.0.0)
        \\    -k, --host-key <file>       Host key file (default: ~/.ssh/sl_host_key)
        \\    -d, --daemon                Run as background daemon
        \\
        \\NOTE: Server validates against system users (like SSH).
        \\      Any user with a system account can connect.
        \\
        \\CLIENT OPTIONS:
        \\    -p, --password <pass>       Use password authentication
        \\    -i, --identity <key>        Use public key authentication
        \\    --strict-host-key           Require host to exist in known hosts
        \\    --accept-new-host-key       Trust on first use (default)
        \\    -P, --port <port>           Server port (default: 2222)
        \\
        \\EXAMPLES:
        \\
        \\  Start server:
        \\    sl server start
        \\    sl server start -p 2222
        \\    sudo sl server start --daemon
        \\
        \\  Connect to server:
        \\    sl shell testuser@192.168.1.100:2222
        \\    sl exec testuser@server.com "ls -la"
        \\    sl sftp testuser@example.com
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

/// Handle session channel and requests
fn handleSession(server_conn: *syslink.connection.ServerConnection, authenticated_user: []const u8) !void {
    var runtime = try syslink.server.session_runtime.SessionRuntime.init(server_conn.allocator, authenticated_user);
    defer runtime.deinit();
    try runtime.run(server_conn);
}

fn serverStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var listen_addr: []const u8 = "0.0.0.0";
    var listen_port: u16 = 2222;
    var daemon_mode = false;
    var foreground_internal = false;
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
        } else if (std.mem.eql(u8, arg, "--foreground-internal")) {
            foreground_internal = true;
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--host-key")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --host-key requires a value\n", .{});
                std.process.exit(1);
            }
            host_key_path = args[i];
        }
    }

    std.debug.print("=== SSH/QUIC Server ===\n\n", .{});
    std.debug.print("Configuration:\n", .{});
    std.debug.print("  Listen: {s}:{d}\n", .{ listen_addr, listen_port });
    std.debug.print("  Daemon: {}\n", .{daemon_mode});
    std.debug.print("  Auth: System users (like SSH)\n\n", .{});

    if (daemon_mode and !foreground_internal) {
        if (readPidFile(allocator)) |existing_pid| {
            if (processAlive(existing_pid)) {
                std.debug.print("Server already running with pid {}\n", .{existing_pid});
                return error.ServerAlreadyRunning;
            }
            removePidFile(allocator);
        } else |_| {}

        const exe_path = try std.fs.selfExePathAlloc(allocator);
        defer allocator.free(exe_path);

        var child_args = std.ArrayListUnmanaged([]const u8){};
        defer child_args.deinit(allocator);

        try child_args.append(allocator, exe_path);
        try child_args.append(allocator, "server");
        try child_args.append(allocator, "start");
        try child_args.append(allocator, "--foreground-internal");
        try child_args.append(allocator, "--host");
        try child_args.append(allocator, listen_addr);

        const port_arg = try std.fmt.allocPrint(allocator, "{}", .{listen_port});
        defer allocator.free(port_arg);
        try child_args.append(allocator, "--port");
        try child_args.append(allocator, port_arg);

        if (host_key_path) |path| {
            try child_args.append(allocator, "--host-key");
            try child_args.append(allocator, path);
        }

        var child = std.process.Child.init(child_args.items, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        try child.spawn();

        try writePidFile(allocator, child.id);
        std.debug.print("✓ Server started in daemon mode (pid {})\n", .{child.id});
        std.debug.print("Use `sl server status` to check health and `sl server stop` to stop it.\n", .{});
        return;
    }

    // Generate or load host key
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();

    var host_private_key: [64]u8 = undefined;
    var host_public_key: [32]u8 = undefined;

    if (host_key_path) |path| {
        var parsed = try syslink.auth.keyfile.parsePrivateKeyFile(allocator, path);
        defer parsed.deinit();

        if (parsed.key_type != .ed25519) {
            std.debug.print("Error: Host key must be Ed25519\n", .{});
            return error.UnsupportedHostKeyType;
        }
        if (parsed.private_key.len != host_private_key.len or parsed.public_key.len != host_public_key.len) {
            std.debug.print("Error: Invalid Ed25519 host key lengths\n", .{});
            return error.InvalidHostKey;
        }

        @memcpy(&host_private_key, parsed.private_key[0..host_private_key.len]);
        @memcpy(&host_public_key, parsed.public_key[0..host_public_key.len]);
        std.debug.print("✓ Loaded host key from {s}\n", .{path});
    } else {
        const Ed25519 = std.crypto.sign.Ed25519;
        const ed_keypair = Ed25519.KeyPair.generate();
        @memcpy(&host_private_key, &ed_keypair.secret_key.bytes);
        @memcpy(&host_public_key, &ed_keypair.public_key.bytes);
    }

    // Encode host key as proper SSH blob
    const host_key_blob = try encodeHostKeyBlob(allocator, &host_public_key);
    defer allocator.free(host_key_blob);

    std.debug.print("Starting server...\n", .{});

    var listener = syslink.connection.startServer(
        allocator,
        listen_addr,
        listen_port,
        host_key_blob,
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

    std.debug.print("Ready for connections. Press Ctrl+C to stop.\n\n", .{});

    // Install signal handler for graceful shutdown
    should_exit.store(false, .release);
    var act = std.posix.Sigaction{
        .handler = .{ .handler = handleSigInt },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // Server loop
    var client_count: usize = 0;
    while (true) {
        if (should_exit.load(.acquire)) break;

        var server_conn = listener.acceptConnection() catch |err| {
            if (err == error.WouldBlock) {
                // No connection ready, wait before trying again
                std.Thread.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            // PacketTooSmall often happens during connection teardown (cleanup packets)
            // These are benign and can be safely ignored
            if (err == error.PacketTooSmall) {
                continue;
            }
            std.debug.print("✗ Failed to accept connection: {}\n\n", .{err});
            continue;
        };
        defer server_conn.deinit();

        client_count += 1;
        std.debug.print("--- Client #{d} ---\n", .{client_count});

        std.debug.print("✓ Client connected\n", .{});

        // Handle authentication - public key only
        const Validators = struct {
            fn keyValidator(user: []const u8, algorithm: []const u8, public_key_blob: []const u8) bool {
                std.debug.print("  → Checking public key for user '{s}' (algorithm: {s})\n", .{ user, algorithm });

                if (syslink.auth.system.validatePublicKey(user, algorithm, public_key_blob)) {
                    std.debug.print("  ✓ Public key authenticated\n", .{});
                    return true;
                }

                std.debug.print("  ✗ Public key not found in authorized_keys\n", .{});
                return false;
            }
        };

        const authenticated_user = server_conn.handleAuthenticationIdentity(
            null,
            Validators.keyValidator,
        ) catch |err| {
            std.debug.print("✗ Authentication error: {}\n\n", .{err});
            continue;
        };

        if (authenticated_user == null) {
            std.debug.print("✗ Authentication failed\n\n", .{});
            continue;
        }
        const user = authenticated_user.?;
        defer allocator.free(user);

        std.debug.print("✓ Client authenticated as {s}\n", .{user});

        // Handle session channels
        handleSession(server_conn, user) catch |err| {
            std.debug.print("✗ Session error: {}\n\n", .{err});
            continue;
        };

        std.debug.print("Session ended\n\n", .{});
    }

    if (foreground_internal) {
        removePidFile(allocator);
    }
    std.debug.print("Server stopped\n", .{});
}

fn pidFilePath(allocator: std.mem.Allocator) ![]u8 {
    const uid = std.posix.getuid();
    const runtime_dir = std.process.getEnvVarOwned(allocator, "XDG_RUNTIME_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (runtime_dir) |dir| allocator.free(dir);

    if (runtime_dir) |dir| {
        return std.fmt.allocPrint(allocator, "{s}/syslink-server-{}.pid", .{ dir, uid });
    }
    return std.fmt.allocPrint(allocator, "/tmp/syslink-server-{}.pid", .{uid});
}

fn validatePidFile(path: []const u8, allocator: std.mem.Allocator) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fd = c.open(path_z.ptr, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return error.FileNotFound;
    defer _ = c.close(fd);

    var st: c.struct_stat = undefined;
    if (c.fstat(fd, &st) != 0) return error.FileNotFound;

    if (st.st_uid != std.posix.getuid()) {
        return error.InvalidPidFileOwner;
    }

    if ((st.st_mode & 0o022) != 0) {
        return error.InsecurePidFilePermissions;
    }
}

fn writePidFile(allocator: std.mem.Allocator, pid: std.process.Child.Id) !void {
    const pid_file = try pidFilePath(allocator);
    defer allocator.free(pid_file);

    var file = try std.fs.cwd().createFile(pid_file, .{ .truncate = true, .mode = 0o600 });
    defer file.close();

    var buffer: [32]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&buffer, "{}\n", .{pid});
    try file.writeAll(pid_text);
}

fn readPidFile(allocator: std.mem.Allocator) !std.posix.pid_t {
    const pid_file = try pidFilePath(allocator);
    defer allocator.free(pid_file);

    try validatePidFile(pid_file, allocator);

    const file = try std.fs.cwd().openFile(pid_file, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 64);
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
    return try std.fmt.parseInt(std.posix.pid_t, trimmed, 10);
}

fn removePidFile(allocator: std.mem.Allocator) void {
    const pid_file = pidFilePath(allocator) catch return;
    defer allocator.free(pid_file);
    std.fs.cwd().deleteFile(pid_file) catch {};
}

fn processAlive(pid: std.posix.pid_t) bool {
    std.posix.kill(pid, 0) catch |err| {
        return err == error.PermissionDenied;
    };
    return true;
}

fn serverStop(allocator: std.mem.Allocator) !void {
    std.debug.print("Stopping SSH/QUIC server...\n", .{});

    const pid = readPidFile(allocator) catch |err| switch (err) {
        error.FileNotFound => {
            const pid_file = pidFilePath(allocator) catch null;
            if (pid_file) |p| {
                defer allocator.free(p);
                std.debug.print("No pid file found ({s}). Server may not be running as daemon.\n", .{p});
            } else {
                std.debug.print("No pid file found (/tmp/syslink-server-<uid>.pid). Server may not be running as daemon.\n", .{});
            }
            return;
        },
        error.InvalidPidFileOwner, error.InsecurePidFilePermissions => {
            return err;
        },
        else => return err,
    };

    if (!processAlive(pid)) {
        std.debug.print("Stale pid file found for pid {}. Cleaning up.\n", .{pid});
        removePidFile(allocator);
        return;
    }

    try std.posix.kill(pid, std.posix.SIG.TERM);

    removePidFile(allocator);
    std.debug.print("✓ Sent SIGTERM to server pid {}\n", .{pid});
}

fn serverStatus(allocator: std.mem.Allocator) !void {
    std.debug.print("Checking server status...\n", .{});

    const pid = readPidFile(allocator) catch |err| switch (err) {
        error.FileNotFound => {
            const pid_file = pidFilePath(allocator) catch null;
            if (pid_file) |p| {
                defer allocator.free(p);
                std.debug.print("Server not running (no pid file at {s}).\n", .{p});
            } else {
                std.debug.print("Server not running (no pid file at /tmp/syslink-server-<uid>.pid).\n", .{});
            }
            return;
        },
        error.InvalidPidFileOwner, error.InsecurePidFilePermissions => {
            return err;
        },
        else => return err,
    };

    if (processAlive(pid)) {
        std.debug.print("✓ Server is running (pid {})\n", .{pid});
    } else {
        std.debug.print("Server is not running, but pid file exists (stale pid {}).\n", .{pid});
    }
}

// ============================================================================
// CLIENT COMMANDS
// ============================================================================

/// Get terminal window size
fn getTerminalSize() !struct { rows: u32, cols: u32 } {
    var ws: c.winsize = undefined;
    if (c.ioctl(std.posix.STDOUT_FILENO, c.TIOCGWINSZ, &ws) == -1) {
        // Default to 80x24 if ioctl fails
        return .{ .rows = 24, .cols = 80 };
    }

    return .{
        .rows = if (ws.ws_row > 0) ws.ws_row else 24,
        .cols = if (ws.ws_col > 0) ws.ws_col else 80,
    };
}

/// Enter terminal raw mode (disables echo, line buffering, etc.)
fn enterRawMode(original: *anyopaque) !void {
    const orig = @as(*c.termios, @ptrCast(@alignCast(original)));

    // Save current terminal settings
    if (c.tcgetattr(std.posix.STDIN_FILENO, orig) != 0) {
        return error.TcGetAttrFailed;
    }

    var raw: c.termios = orig.*;

    // Input modes - disable break, CR->NL, parity, strip, flow control
    raw.c_iflag &= ~@as(c_uint, c.BRKINT | c.ICRNL | c.INPCK | c.ISTRIP | c.IXON);

    // Output modes - disable post processing
    raw.c_oflag &= ~@as(c_uint, c.OPOST);

    // Control modes - set 8 bit chars
    raw.c_cflag |= @as(c_uint, c.CS8);

    // Local modes - disable echo, canonical, extended input, signals
    raw.c_lflag &= ~@as(c_uint, c.ECHO | c.ICANON | c.IEXTEN | c.ISIG);

    // Set read to return immediately
    raw.c_cc[c.VMIN] = 0;
    raw.c_cc[c.VTIME] = 0;

    // Apply immediately
    if (c.tcsetattr(std.posix.STDIN_FILENO, c.TCSAFLUSH, &raw) != 0) {
        return error.TcSetAttrFailed;
    }
}

/// Restore terminal to original mode
fn restoreTerminalMode(original: *const anyopaque) void {
    const orig = @as(*const c.termios, @ptrCast(@alignCast(original)));
    _ = c.tcsetattr(std.posix.STDIN_FILENO, c.TCSAFLUSH, orig);
}

fn getPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]const u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    try stdout.writeAll(prompt);

    // Disable echo using termios
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

fn authenticateClient(
    allocator: std.mem.Allocator,
    conn: *syslink.connection.ClientConnection,
    username: []const u8,
    password_arg: ?[]const u8,
    identity_path: ?[]const u8,
) !bool {
    if (identity_path) |path| {
        var parsed = try syslink.auth.keyfile.parsePrivateKeyFile(allocator, path);
        defer parsed.deinit();

        if (parsed.key_type != .ed25519) {
            return error.UnsupportedKeyType;
        }
        if (parsed.public_key.len != 32 or parsed.private_key.len != 64) {
            return error.InvalidKeyMaterial;
        }

        var public_key: [32]u8 = undefined;
        @memcpy(&public_key, parsed.public_key[0..32]);
        var private_key: [64]u8 = undefined;
        @memcpy(&private_key, parsed.private_key[0..64]);

        const public_key_blob = try encodeHostKeyBlob(allocator, &public_key);
        defer allocator.free(public_key_blob);

        const authed = try conn.authenticatePublicKey(
            username,
            parsed.algorithm_name,
            public_key_blob,
            &private_key,
        );
        if (authed) return true;
    }

    const password_owned = if (password_arg == null)
        try getPassword(allocator, "Password: ")
    else
        null;
    defer if (password_owned) |pw| allocator.free(pw);

    const password = password_arg orelse password_owned.?;
    return try conn.authenticatePassword(username, password);
}

fn connectClientWithHostTrust(
    allocator: std.mem.Allocator,
    hostname: []const u8,
    port: u16,
    random: std.Random,
    policy: syslink.connection.HostKeyTrustPolicy,
) !syslink.connection.ClientConnection {
    return syslink.connection.connectClientTrusted(allocator, hostname, port, random, policy);
}

fn runShellCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl shell [options] [user@]host[:port]\n", .{});
        std.debug.print("Options:\n", .{});
        std.debug.print("  -p, --password <pass>  Password for authentication\n", .{});
        std.debug.print("  -i, --identity <key>   Private key for public key authentication\n", .{});
        std.debug.print("  --strict-host-key      Require host in known hosts\n", .{});
        std.debug.print("  --accept-new-host-key  Trust unknown host and persist (default)\n", .{});
        std.process.exit(1);
    }

    // Parse options
    var password_arg: ?[]const u8 = null;
    var identity_path: ?[]const u8 = null;
    var trust_policy: syslink.connection.HostKeyTrustPolicy = .accept_new;
    var host_arg: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--password")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -p requires a password argument\n", .{});
                std.process.exit(1);
            }
            i += 1;
            password_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -i requires a key file path\n", .{});
                std.process.exit(1);
            }
            i += 1;
            identity_path = args[i];
        } else if (std.mem.eql(u8, arg, "--strict-host-key")) {
            trust_policy = .strict;
        } else if (std.mem.eql(u8, arg, "--accept-new-host-key")) {
            trust_policy = .accept_new;
        } else if (arg[0] != '-') {
            host_arg = arg;
        }
    }

    if (host_arg == null) {
        std.debug.print("Error: Host required\n", .{});
        std.process.exit(1);
    }

    const host = host_arg.?;
    var username: []const u8 = "root";
    var hostname: []const u8 = undefined;
    var port: u16 = 2222;

    if (std.mem.indexOf(u8, host, "@")) |at_pos| {
        username = host[0..at_pos];
        hostname = host[at_pos + 1 ..];
    } else {
        hostname = host;
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

    var conn = connectClientWithHostTrust(allocator, hostname, port, random, trust_policy) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.debug.print("\nTroubleshooting:\n", .{});
        std.debug.print("  • Check server is running: nc -u -v {s} {d}\n", .{ hostname, port });
        std.debug.print("  • Verify firewall allows UDP port {d}\n", .{port});
        std.debug.print("  • Try pinging the host: ping {s}\n", .{hostname});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ Connected\n", .{});

    const auth_success = authenticateClient(allocator, &conn, username, password_arg, identity_path) catch |err| {
        std.debug.print("✗ Authentication failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (!auth_success) {
        std.debug.print("✗ Authentication failed\n", .{});
        std.process.exit(1);
    }

    std.debug.print("✓ Authenticated\n\n", .{});

    // Get terminal size
    const term_size = try getTerminalSize();

    var session = conn.requestShell(term_size.cols, term_size.rows) catch |err| {
        std.debug.print("✗ Failed to start shell: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        session.close() catch {};
    }

    std.debug.print("Shell session active. Type commands or 'exit' to quit.\n\n", .{});

    // Enter raw mode for proper terminal handling
    var original_termios: c.termios = undefined;
    const entered_raw_mode = blk: {
        enterRawMode(&original_termios) catch {
            std.debug.print("Warning: Could not enter raw mode\n", .{});
            break :blk false;
        };
        break :blk true;
    };
    defer {
        if (entered_raw_mode) {
            restoreTerminalMode(&original_termios);
        }
    }

    // Set up signal handler for clean exit on Ctrl+C
    var act = std.posix.Sigaction{
        .handler = .{ .handler = handleSigInt },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);

    runShellInteractive(allocator, &session) catch |err| {
        std.debug.print("\r\nSession error: {}\r\n", .{err});
    };

    // Reset exit flag for future connections
    should_exit.store(false, .release);

    // Force terminal restore before any cleanup
    if (entered_raw_mode) {
        restoreTerminalMode(&original_termios);
    }
}

fn runShellInteractive(allocator: std.mem.Allocator, session: *syslink.channels.SessionChannel) !void {
    _ = allocator;
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    var running = true;
    var stdin_buffer: [16384]u8 = undefined;

    // Optimized I/O loop for low latency
    while (running) {
        // Check if user pressed Ctrl+C
        if (should_exit.load(.acquire)) {
            break;
        }

        // Poll with minimal timeout (1ms)
        session.manager.transport.poll(1) catch {};

        // Check for stdin input (non-blocking)
        const stdin_len: usize = stdin.read(&stdin_buffer) catch |err| blk: {
            if (err == error.WouldBlock) break :blk 0;
            if (err == error.EOF or err == error.EndOfStream) {
                running = false;
                break :blk 0;
            }
            break :blk 0;
        };

        // Forward stdin to server
        if (stdin_len > 0) {
            session.sendData(stdin_buffer[0..stdin_len]) catch |err| {
                std.debug.print("\r\nError sending data: {}\r\n", .{err});
                running = false;
                continue;
            };
        }

        // Check for server output (non-blocking)
        if (session.receiveData()) |data| {
            defer session.manager.allocator.free(data);
            stdout.writeAll(data) catch {};
        } else |err| {
            // Handle errors
            if (err == error.StreamClosed) {
                // Stream closed by server - clean exit
                running = false;
            } else if (err == error.InvalidMessageType) {
                // Got EOF or other non-data message
                std.debug.print("\r\n[CLIENT] Received EOF from server, exiting\r\n", .{});
                running = false;
            } else if (err != error.NoData and err != error.EndOfBuffer) {
                // Real error - exit
                std.debug.print("\r\n[CLIENT] Connection error: {}, exiting\r\n", .{err});
                running = false;
            }
        }
    }

    stdout.writeAll("\r\nConnection closed\r\n") catch {};
}

fn runExecCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        std.debug.print("Error: Host and command required\n", .{});
        std.debug.print("Usage: sl exec [options] [user@]host[:port] <command>\n", .{});
        std.debug.print("Options:\n", .{});
        std.debug.print("  -p, --password <pass>  Password for authentication\n", .{});
        std.debug.print("  -i, --identity <key>   Private key for public key authentication\n", .{});
        std.debug.print("  --strict-host-key      Require host in known hosts\n", .{});
        std.debug.print("  --accept-new-host-key  Trust unknown host and persist (default)\n", .{});
        std.debug.print("Example: sl exec user@host \"ls -la\"\n", .{});
        std.process.exit(1);
    }

    var password_arg: ?[]const u8 = null;
    var identity_path: ?[]const u8 = null;
    var trust_policy: syslink.connection.HostKeyTrustPolicy = .accept_new;
    var positionals = std.ArrayListUnmanaged([]const u8){};
    defer positionals.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--password")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -p requires a password argument\n", .{});
                std.process.exit(1);
            }
            i += 1;
            password_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -i requires a key file path\n", .{});
                std.process.exit(1);
            }
            i += 1;
            identity_path = args[i];
        } else if (std.mem.eql(u8, arg, "--strict-host-key")) {
            trust_policy = .strict;
        } else if (std.mem.eql(u8, arg, "--accept-new-host-key")) {
            trust_policy = .accept_new;
        } else {
            try positionals.append(allocator, arg);
        }
    }

    if (positionals.items.len < 2) {
        std.debug.print("Error: Host and command required\n", .{});
        std.process.exit(1);
    }

    const host_arg = positionals.items[0];
    var command_buf = std.ArrayListUnmanaged(u8){};
    defer command_buf.deinit(allocator);
    for (positionals.items[1..], 0..) |part, idx| {
        if (idx > 0) try command_buf.append(allocator, ' ');
        try command_buf.appendSlice(allocator, part);
    }
    const command = command_buf.items;

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

    var conn = connectClientWithHostTrust(allocator, hostname, port, random, trust_policy) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

    const auth_success = authenticateClient(allocator, &conn, username, password_arg, identity_path) catch |err| {
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

    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    const stderr = std.fs.File{ .handle = std.posix.STDERR_FILENO };

    var buffer: [65536]u8 = undefined;
    var exit_status: ?u32 = null;

    while (true) {
        conn.transport.poll(5000) catch {};

        const len = conn.transport.receiveFromStream(session.stream_id, &buffer) catch |err| {
            if (err == error.NoData) continue;
            if (err == error.EndOfStream) break;
            std.debug.print("✗ Failed to read exec output: {}\n", .{err});
            return;
        };
        if (len == 0) continue;

        const packet = buffer[0..len];
        if (packet.len == 0) continue;

        switch (packet[0]) {
            94 => { // SSH_MSG_CHANNEL_DATA
                var msg = syslink.ChannelData.decode(allocator, packet) catch continue;
                defer msg.deinit(allocator);
                try stdout.writeAll(msg.data);
            },
            95 => { // SSH_MSG_CHANNEL_EXTENDED_DATA
                var msg = syslink.ChannelExtendedData.decode(allocator, packet) catch continue;
                defer msg.deinit(allocator);
                if (msg.data_type_code == 1) {
                    try stderr.writeAll(msg.data);
                } else {
                    try stdout.writeAll(msg.data);
                }
            },
            98 => { // SSH_MSG_CHANNEL_REQUEST (exit-status)
                var req = syslink.ChannelRequest.decode(allocator, packet) catch continue;
                defer req.deinit(allocator);

                if (std.mem.eql(u8, req.request_type, "exit-status") and req.type_specific_data.len >= 4) {
                    exit_status = std.mem.readInt(u32, req.type_specific_data[0..4], .big);
                }
            },
            96, 97 => break, // EOF or CLOSE
            else => {},
        }
    }

    if (exit_status) |code| {
        if (code != 0) {
            std.process.exit(@intCast(code));
        }
    }
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl sftp [options] [user@]host[:port]\n", .{});
        std.debug.print("Options:\n", .{});
        std.debug.print("  -p, --password <pass>  Password for authentication\n", .{});
        std.debug.print("  -i, --identity <key>   Private key for public key authentication\n", .{});
        std.debug.print("  --strict-host-key      Require host in known hosts\n", .{});
        std.debug.print("  --accept-new-host-key  Trust unknown host and persist (default)\n", .{});
        std.process.exit(1);
    }

    var password_arg: ?[]const u8 = null;
    var identity_path: ?[]const u8 = null;
    var trust_policy: syslink.connection.HostKeyTrustPolicy = .accept_new;
    var host_arg: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--password")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -p requires a password argument\n", .{});
                std.process.exit(1);
            }
            i += 1;
            password_arg = args[i];
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: -i requires a key file path\n", .{});
                std.process.exit(1);
            }
            i += 1;
            identity_path = args[i];
        } else if (std.mem.eql(u8, arg, "--strict-host-key")) {
            trust_policy = .strict;
        } else if (std.mem.eql(u8, arg, "--accept-new-host-key")) {
            trust_policy = .accept_new;
        } else if (arg[0] != '-') {
            host_arg = arg;
        }
    }

    if (host_arg == null) {
        std.debug.print("Error: Host required\n", .{});
        std.process.exit(1);
    }

    const host_arg_val = host_arg.?;

    var username: []const u8 = "root";
    var hostname: []const u8 = undefined;
    var port: u16 = 2222;

    if (std.mem.indexOf(u8, host_arg_val, "@")) |at_pos| {
        username = host_arg_val[0..at_pos];
        hostname = host_arg_val[at_pos + 1 ..];
    } else {
        hostname = host_arg_val;
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

    var conn = connectClientWithHostTrust(allocator, hostname, port, random, trust_policy) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ Connected\n", .{});

    const auth_success = authenticateClient(allocator, &conn, username, password_arg, identity_path) catch |err| {
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

    const current_dir = "/"; // Simplified for demo

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

/// Encode Ed25519 public key as SSH host key blob
/// Format: string("ssh-ed25519") || string(32-byte public key)
fn encodeHostKeyBlob(allocator: std.mem.Allocator, public_key: *const [32]u8) ![]u8 {
    const algorithm = "ssh-ed25519";
    const blob_size = 4 + algorithm.len + 4 + public_key.len;
    const blob = try allocator.alloc(u8, blob_size);
    errdefer allocator.free(blob);

    var offset: usize = 0;

    // Write algorithm name length + name
    std.mem.writeInt(u32, blob[offset..][0..4], @intCast(algorithm.len), .big);
    offset += 4;
    @memcpy(blob[offset .. offset + algorithm.len], algorithm);
    offset += algorithm.len;

    // Write public key length + key
    std.mem.writeInt(u32, blob[offset..][0..4], @intCast(public_key.len), .big);
    offset += 4;
    @memcpy(blob[offset .. offset + public_key.len], public_key);

    return blob;
}
// Clean build
