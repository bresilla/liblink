const std = @import("std");
const connection = @import("../connection.zig");
const channels = @import("../channels/channels.zig");
const channel_protocol = @import("../protocol/channel.zig");
const wire = @import("../protocol/wire.zig");
const pty = @import("../platform/pty.zig");
const user = @import("../platform/user.zig");
const sftp = @import("../sftp/sftp.zig");

pub const SessionMode = enum {
    shell,
    exec,
    subsystem_sftp,
};

const PtyRequestInfo = struct {
    term: []const u8,
    width_chars: u32,
    height_rows: u32,
    width_pixels: u32,
    height_pixels: u32,
    modes: []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *PtyRequestInfo) void {
        self.allocator.free(self.term);
        self.allocator.free(self.modes);
    }
};

const PtySession = struct {
    pty: *pty.Pty,
    pid: std.posix.pid_t,
    allocator: std.mem.Allocator,

    fn deinit(self: *PtySession) void {
        // Send SIGTERM so the child shell exits cleanly
        std.posix.kill(self.pid, std.posix.SIG.TERM) catch {};

        // Give the process a moment to exit gracefully
        var exited = false;
        for (0..10) |_| {
            const wait_result = std.posix.waitpid(self.pid, std.c.W.NOHANG);
            if (wait_result.pid != 0) {
                exited = true;
                break;
            }
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }

        // Force kill if still running
        if (!exited) {
            std.posix.kill(self.pid, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(self.pid, 0);
        }

        self.pty.deinit();
        self.allocator.destroy(self.pty);
    }
};

pub const SessionRuntime = struct {
    allocator: std.mem.Allocator,
    authenticated_user: []u8,

    active_shells: std.AutoHashMap(u64, PtySession),
    active_exec: std.AutoHashMap(u64, []u8),
    session_modes: std.AutoHashMap(u64, SessionMode),
    pty_requests: std.AutoHashMap(u64, PtyRequestInfo),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, authenticated_user: []const u8) !Self {
        return .{
            .allocator = allocator,
            .authenticated_user = try allocator.dupe(u8, authenticated_user),
            .active_shells = std.AutoHashMap(u64, PtySession).init(allocator),
            .active_exec = std.AutoHashMap(u64, []u8).init(allocator),
            .session_modes = std.AutoHashMap(u64, SessionMode).init(allocator),
            .pty_requests = std.AutoHashMap(u64, PtyRequestInfo).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var shell_it = self.active_shells.iterator();
        while (shell_it.next()) |entry| {
            var session = entry.value_ptr.*;
            session.deinit();
        }
        self.active_shells.deinit();

        var exec_it = self.active_exec.iterator();
        while (exec_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.active_exec.deinit();

        var pty_it = self.pty_requests.iterator();
        while (pty_it.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit();
        }
        self.pty_requests.deinit();

        self.session_modes.deinit();
        self.allocator.free(self.authenticated_user);
    }

    pub fn run(self: *Self, server_conn: *connection.ServerConnection) !void {
        const stream_id = try self.waitForSessionChannel(server_conn, 30000);

        if (self.active_shells.fetchRemove(stream_id)) |entry| {
            var old = entry.value;
            old.deinit();
        }

        var session_started = false;
        const session_deadline = std.time.milliTimestamp() + 30000;
        while (!session_started) {
            if (std.time.milliTimestamp() >= session_deadline) {
                return error.SessionRequestTimeout;
            }

            server_conn.transport.poll(100) catch {};

            var buffer: [4096]u8 = undefined;
            const len = server_conn.transport.receiveFromStream(stream_id, &buffer) catch 0;
            if (len == 0) continue;

            var request_info = try server_conn.channel_manager.handleRequest(stream_id, buffer[0..len]);
            defer request_info.deinit(self.allocator);

            self.handleRequest(server_conn, stream_id, &request_info) catch |err| {
                std.log.debug("Session request handling error: {}", .{err});
            };

            if (self.session_modes.get(stream_id)) |_| {
                session_started = true;
            }
        }

        const mode = self.session_modes.get(stream_id) orelse return error.NoSessionMode;
        switch (mode) {
            .shell => try self.bridgeSession(server_conn, stream_id),
            .exec => try self.runExecRequest(server_conn, stream_id),
            .subsystem_sftp => try self.runSftpSubsystem(server_conn, stream_id),
        }
    }

    fn waitForSessionChannel(self: *Self, server_conn: *connection.ServerConnection, timeout_ms: u32) !u64 {
        _ = self;

        const deadline_ms = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (std.time.milliTimestamp() < deadline_ms) {
            server_conn.transport.poll(50) catch {};

            const stream_id = server_conn.acceptChannel() catch |err| {
                std.log.debug("acceptChannel while waiting for session: {}", .{err});
                std.Thread.sleep(2 * std.time.ns_per_ms);
                continue;
            };
            return stream_id;
        }

        return error.ChannelAcceptTimeout;
    }

    fn handleRequest(self: *Self, server_conn: *connection.ServerConnection, stream_id: u64, request_info: *channels.ChannelRequestInfo) !void {
        const req = request_info.request;
        const want_reply = req.want_reply;

        if (std.mem.eql(u8, req.request_type, "pty-req")) {
            self.handlePtyRequest(stream_id, req.type_specific_data) catch |err| {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return err;
            };
        } else if (std.mem.eql(u8, req.request_type, "shell")) {
            self.handleShellRequest(stream_id) catch |err| {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return err;
            };
        } else if (std.mem.eql(u8, req.request_type, "exec")) {
            var reader = wire.Reader{ .buffer = req.type_specific_data };
            const command = reader.readString(self.allocator) catch |err| {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return err;
            };
            defer self.allocator.free(command);
            self.handleExecRequest(stream_id, command) catch |err| {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return err;
            };
        } else if (std.mem.eql(u8, req.request_type, "subsystem")) {
            var reader = wire.Reader{ .buffer = req.type_specific_data };
            const subsystem_name = reader.readString(self.allocator) catch |err| {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return err;
            };
            defer self.allocator.free(subsystem_name);
            if (!std.mem.eql(u8, subsystem_name, "sftp")) {
                if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
                return error.UnsupportedSubsystem;
            }
            try self.session_modes.put(stream_id, .subsystem_sftp);
        } else {
            if (want_reply) server_conn.channel_manager.sendFailure(stream_id) catch {};
            return error.UnsupportedRequest;
        }

        if (want_reply) {
            server_conn.channel_manager.sendSuccess(stream_id) catch {};
        }
    }

    fn handlePtyRequest(self: *Self, stream_id: u64, type_specific_data: []const u8) !void {
        var reader = wire.Reader{ .buffer = type_specific_data };
        const term = try reader.readString(self.allocator);
        errdefer self.allocator.free(term);
        const width_chars = try reader.readUint32();
        const height_rows = try reader.readUint32();
        const width_pixels = try reader.readUint32();
        const height_pixels = try reader.readUint32();
        const modes = try reader.readString(self.allocator);
        errdefer self.allocator.free(modes);

        const info = PtyRequestInfo{
            .term = try self.allocator.dupe(u8, term),
            .width_chars = width_chars,
            .height_rows = height_rows,
            .width_pixels = width_pixels,
            .height_pixels = height_pixels,
            .modes = try self.allocator.dupe(u8, modes),
            .allocator = self.allocator,
        };

        if (self.pty_requests.fetchRemove(stream_id)) |entry| {
            var old = entry.value;
            old.deinit();
        }
        try self.pty_requests.put(stream_id, info);
    }

    fn handleShellRequest(self: *Self, stream_id: u64) !void {
        const pty_info = self.pty_requests.get(stream_id);

        const p = try self.allocator.create(pty.Pty);
        errdefer self.allocator.destroy(p);
        p.* = try pty.Pty.create(self.allocator);
        errdefer p.deinit();

        if (pty_info) |info| {
            try p.setWindowSize(@intCast(info.height_rows), @intCast(info.width_chars));
        } else {
            try p.setWindowSize(24, 80);
        }

        var account = try user.lookup(self.allocator, self.authenticated_user);
        defer account.deinit();

        var term_buf: [256]u8 = undefined;
        var term_ptr: [*:0]const u8 = "xterm-256color";
        if (pty_info) |info| {
            if (info.term.len > 0 and info.term.len < term_buf.len - 1 and isValidTermName(info.term)) {
                @memcpy(term_buf[0..info.term.len], info.term);
                term_buf[info.term.len] = 0;
                term_ptr = @ptrCast(term_buf[0..info.term.len :0]);
            }
        }

        const shell_env = pty.ShellEnv{
            .term = term_ptr,
            .home = account.home_z.ptr,
            .shell = account.shell_z.ptr,
            .user = account.username_z.ptr,
            .logname = account.username_z.ptr,
            .uid = account.uid,
            .gid = account.gid,
        };

        const pid = try pty.spawnShell(p, shell_env);

        try self.active_shells.put(stream_id, .{
            .pty = p,
            .pid = pid,
            .allocator = self.allocator,
        });
        try self.session_modes.put(stream_id, .shell);
    }

    fn handleExecRequest(self: *Self, stream_id: u64, command: []const u8) !void {
        const command_copy = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(command_copy);

        if (self.active_exec.fetchRemove(stream_id)) |entry| {
            self.allocator.free(entry.value);
        }

        try self.active_exec.put(stream_id, command_copy);
        try self.session_modes.put(stream_id, .exec);
    }

    fn sendExitStatus(server_conn: *connection.ServerConnection, stream_id: u64, status: u32) !void {
        var status_data: [4]u8 = undefined;
        std.mem.writeInt(u32, &status_data, status, .big);
        try server_conn.channel_manager.sendRequest(stream_id, "exit-status", false, &status_data);
    }

    fn runExecRequest(self: *Self, server_conn: *connection.ServerConnection, stream_id: u64) !void {
        const command = if (self.active_exec.fetchRemove(stream_id)) |entry|
            entry.value
        else
            return error.MissingExecRequest;
        defer self.allocator.free(command);

        var account = try user.lookup(self.allocator, self.authenticated_user);
        defer account.deinit();

        const result = try user.runCommandAsUser(self.allocator, &account, command, 16 * 1024 * 1024);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.stdout.len > 0) {
            try server_conn.channel_manager.sendData(stream_id, result.stdout);
        }
        if (result.stderr.len > 0) {
            try server_conn.channel_manager.sendExtendedData(stream_id, 1, result.stderr);
        }

        var exit_code: u32 = 1;
        switch (result.term) {
            .Exited => |code| exit_code = code,
            .Signal => |sig| exit_code = 128 + @as(u32, @intCast(sig)),
            else => {},
        }

        try sendExitStatus(server_conn, stream_id, exit_code);
        server_conn.channel_manager.sendEof(stream_id) catch {};
        server_conn.channel_manager.closeChannel(stream_id) catch {};
        _ = self.session_modes.fetchRemove(stream_id);
    }

    fn runSftpSubsystem(self: *Self, server_conn: *connection.ServerConnection, stream_id: u64) !void {
        var root_buf: [4096]u8 = undefined;
        var derived_root: ?[]u8 = null;
        defer if (derived_root) |root| self.allocator.free(root);

        const sftp_root = std.process.getEnvVarOwned(self.allocator, "SL_SFTP_ROOT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (sftp_root) |root| self.allocator.free(root);

        const remote_root = if (sftp_root) |root|
            root
        else blk: {
            if (user.lookup(self.allocator, self.authenticated_user)) |account| {
                defer {
                    var m = account;
                    m.deinit();
                }
                derived_root = try self.allocator.dupe(u8, account.home_z);
                break :blk derived_root.?;
            } else |_| {}

            const cwd = try std.posix.getcwd(&root_buf);
            break :blk cwd;
        };

        const session_channel = channels.SessionChannel{
            .manager = &server_conn.channel_manager,
            .stream_id = stream_id,
            .allocator = self.allocator,
        };

        const sftp_channel = sftp.SftpChannel.init(self.allocator, session_channel);
        var sftp_server = try sftp.SftpServer.initWithOptions(self.allocator, sftp_channel, .{ .remote_root = remote_root });
        defer sftp_server.deinit();

        sftp_server.run() catch |err| {
            if (err != error.EndOfStream and err != error.ConnectionClosed) return err;
        };

        server_conn.channel_manager.sendEof(stream_id) catch {};
        server_conn.channel_manager.closeChannel(stream_id) catch {};
        _ = self.session_modes.fetchRemove(stream_id);
    }

    fn isValidTermName(term: []const u8) bool {
        for (term) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') {
                return false;
            }
        }
        return true;
    }

    fn bridgeSession(self: *Self, server_conn: *connection.ServerConnection, stream_id: u64) !void {
        const session = self.active_shells.get(stream_id) orelse return error.NoPtyForSession;
        const p = session.pty;

        var pty_buffer: [16384]u8 = undefined;
        var channel_buffer: [16384]u8 = undefined;

        const flags = try std.posix.fcntl(p.master_fd, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(p.master_fd, std.posix.F.SETFL, flags | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));

        while (true) {
            server_conn.transport.poll(1) catch {};

            const channel_len = server_conn.transport.receiveFromStream(stream_id, &channel_buffer) catch 0;
            if (channel_len > 0) {
                const data = channel_buffer[0..channel_len];

                if (data.len > 0 and data[0] == 94) {
                    var channel_data = channel_protocol.ChannelData.decode(self.allocator, data) catch continue;
                    defer channel_data.deinit(self.allocator);
                    _ = p.write(channel_data.data) catch break;
                } else if (data.len > 0 and data[0] == 96) {
                    break;
                }
            }

            const pty_len = p.read(&pty_buffer) catch |err| {
                if (err == error.WouldBlock) {
                    // Check if child process has exited
                    const wait_result = std.posix.waitpid(session.pid, std.c.W.NOHANG);
                    if (wait_result.pid != 0) break; // child exited
                    continue;
                }
                server_conn.channel_manager.sendEof(stream_id) catch {};
                server_conn.channel_manager.closeChannel(stream_id) catch {};
                break;
            };

            if (pty_len == 0) break; // EOF — child exited

            try server_conn.channel_manager.sendData(stream_id, pty_buffer[0..pty_len]);
        }

        server_conn.channel_manager.sendEof(stream_id) catch {};
        server_conn.channel_manager.closeChannel(stream_id) catch {};

        if (self.active_shells.fetchRemove(stream_id)) |entry| {
            var pty_session = entry.value;
            pty_session.deinit();
        }

        if (self.pty_requests.fetchRemove(stream_id)) |entry| {
            var info = entry.value;
            info.deinit();
        }

        _ = self.session_modes.fetchRemove(stream_id);
    }
};
