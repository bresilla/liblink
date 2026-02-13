const std = @import("std");
const posix = std.posix;

/// PTY (Pseudo-Terminal) for shell sessions
///
/// Platform-specific implementation for Linux/Unix
pub const Pty = struct {
    master_fd: posix.fd_t,
    slave_path: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Create a new PTY pair
    pub fn create(allocator: std.mem.Allocator) !Self {
        // Open PTY master
        const master_fd = try posix.open(
            "/dev/ptmx",
            .{ .ACCMODE = .RDWR, .NOCTTY = true },
            0,
        );
        errdefer posix.close(master_fd);

        // Grant access and unlock
        if (std.c.grantpt(master_fd) != 0) {
            return error.GrantPtFailed;
        }

        if (std.c.unlockpt(master_fd) != 0) {
            return error.UnlockPtFailed;
        }

        // Get slave device name
        const slave_name = std.c.ptsname(master_fd) orelse return error.PtsnameFailed;
        const slave_path = try allocator.dupe(u8, std.mem.span(slave_name));
        errdefer allocator.free(slave_path);

        return Self{
            .master_fd = master_fd,
            .slave_path = slave_path,
            .allocator = allocator,
        };
    }

    /// Clean up PTY
    pub fn deinit(self: *Self) void {
        posix.close(self.master_fd);
        self.allocator.free(self.slave_path);
    }

    /// Read data from PTY master (shell output)
    pub fn read(self: *Self, buffer: []u8) !usize {
        return posix.read(self.master_fd, buffer);
    }

    /// Write data to PTY master (shell input)
    pub fn write(self: *Self, data: []const u8) !usize {
        return posix.write(self.master_fd, data);
    }

    /// Set terminal window size
    pub fn setWindowSize(self: *Self, rows: u16, cols: u16) !void {
        const winsize = std.c.winsize{
            .ws_row = rows,
            .ws_col = cols,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };

        if (std.c.ioctl(self.master_fd, std.c.T.IOCSWINSZ, @intFromPtr(&winsize)) != 0) {
            return error.IoctlFailed;
        }
    }
};

/// Spawn a shell in a PTY
pub fn spawnShell(pty: *Pty, username: []const u8) !posix.pid_t {
    _ = username; // TODO: Look up user's shell from /etc/passwd

    const pid = try posix.fork();

    if (pid == 0) {
        // Child process
        childSetup(pty) catch |err| {
            std.debug.print("Child setup failed: {}\n", .{err});
            std.process.exit(1);
        };
        // If we get here, exec failed
        std.process.exit(1);
    }

    // Parent process - return child PID
    return pid;
}

/// Child process setup (runs in forked child)
fn childSetup(pty: *Pty) !void {
    // Create new session
    if (std.c.setsid() < 0) {
        return error.SetsidFailed;
    }

    // Open PTY slave
    const slave_fd = try posix.open(
        pty.slave_path,
        .{ .ACCMODE = .RDWR },
        0,
    );
    errdefer posix.close(slave_fd);

    // Make slave the controlling terminal
    if (std.c.ioctl(slave_fd, std.c.T.IOCSCTTY, @as(c_int, 0)) != 0) {
        return error.IoctlFailed;
    }

    // Redirect stdin, stdout, stderr to PTY slave
    try posix.dup2(slave_fd, 0); // stdin
    try posix.dup2(slave_fd, 1); // stdout
    try posix.dup2(slave_fd, 2); // stderr

    // Close original slave fd if it's not 0, 1, or 2
    if (slave_fd > 2) {
        posix.close(slave_fd);
    }

    // Close master fd (child doesn't need it)
    posix.close(pty.master_fd);

    // Set environment
    try posix.setenv("TERM", "xterm-256color", 1);

    // Execute shell
    const shell = "/bin/bash";
    const argv = [_:null]?[*:0]const u8{
        shell,
        "-i", // Interactive
        null,
    };

    const envp = [_:null]?[*:0]const u8{
        "TERM=xterm-256color",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        null,
    };

    // exec never returns on success
    const err = posix.execveZ(shell, &argv, &envp);
    return err;
}
