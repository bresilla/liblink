const std = @import("std");
const voidbox = @import("voidbox");

const VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Simple hardcoded test for now - just test the shell command
    std.debug.print("sl - SSH/QUIC CLI tool (version {s})\n\n", .{VERSION});

    // For testing, hardcode a connection attempt
    std.debug.print("Testing SSH/QUIC connection to 127.0.0.1:2222...\n\n", .{});

    try runShellCommand(allocator, &[_][]const u8{"127.0.0.1"});
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

fn runShellCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.debug.print("Error: Host required\n", .{});
        std.debug.print("Usage: sl shell [user@]host\n", .{});
        std.process.exit(1);
    }

    const host_arg = args[0];

    // Parse [user@]host[:port]
    var username: ?[]const u8 = null;
    var hostname: []const u8 = undefined;
    var port: u16 = 22;

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

    std.debug.print("Connecting to {s}:{d}", .{ hostname, port });
    if (username) |user| {
        std.debug.print(" as {s}", .{user});
    }
    std.debug.print("...\n", .{});

    // Initialize random number generator
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Create connection config
    const config = voidbox.connection.ConnectionConfig{
        .server_address = hostname,
        .server_port = port,
        .random = random,
    };

    // Attempt to connect
    std.debug.print("Initiating SSH/QUIC handshake...\n", .{});
    var conn = voidbox.connection.ClientConnection.connect(allocator, config) catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.debug.print("\nThis is expected if no server is running.\n", .{});
        std.debug.print("To test with a real server:\n", .{});
        std.debug.print("  1. Run a test server on port {d}\n", .{port});
        std.debug.print("  2. Server must implement SSH/QUIC protocol\n", .{});
        std.process.exit(1);
    };
    defer conn.deinit();

    std.debug.print("✓ SSH/QUIC connection established!\n\n", .{});
    std.debug.print("TODO: Interactive shell not yet implemented\n", .{});
    std.debug.print("Next steps:\n", .{});
    std.debug.print("  - Implement SSH authentication (password/pubkey)\n", .{});
    std.debug.print("  - Implement channel protocol for shell session\n", .{});
    std.debug.print("  - Handle terminal I/O\n", .{});
}

fn runDaemonCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    _ = args;
    std.debug.print("TODO: Run as background daemon\n", .{});
}

fn runSftpCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    _ = args;
    std.debug.print("TODO: SFTP commands\n", .{});
}
