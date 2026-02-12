const std = @import("std");
const Allocator = std.mem.Allocator;
const ChannelManager = @import("manager.zig").ChannelManager;
const channel_protocol = @import("../protocol/channel.zig");
const wire = @import("../protocol/wire.zig");

/// Session Channel
///
/// Implements "session" channel type for interactive shells,
/// command execution, and subsystems (like SFTP).
///
/// Per RFC 4254 Section 6.

pub const SessionChannel = struct {
    manager: *ChannelManager,
    stream_id: u64,
    allocator: Allocator,

    const Self = @This();

    /// Open a new session channel
    pub fn open(allocator: Allocator, manager: *ChannelManager) !Self {
        const stream_id = try manager.openChannel(
            "session",
            2 * 1024 * 1024, // 2MB initial window size
            32 * 1024, // 32KB max packet size
            "", // No type-specific data for session
        );

        return Self{
            .manager = manager,
            .stream_id = stream_id,
            .allocator = allocator,
        };
    }

    /// Wait for channel to be confirmed open
    ///
    /// Reads the CHANNEL_OPEN_CONFIRMATION message.
    pub fn waitForConfirmation(self: *Self) !void {
        var buffer: [4096]u8 = undefined;
        const len = try self.manager.transport.receiveFromStream(self.stream_id, &buffer);
        const data = buffer[0..len];

        if (data.len < 1) {
            return error.InvalidResponse;
        }

        const msg_type = data[0];
        switch (msg_type) {
            91 => { // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
                try self.manager.handleOpenConfirmation(self.stream_id, data);
            },
            92 => { // SSH_MSG_CHANNEL_OPEN_FAILURE
                try self.manager.handleOpenFailure(self.stream_id, data);
                return error.ChannelOpenFailed;
            },
            else => {
                std.log.err("Unexpected message type: {}", .{msg_type});
                return error.UnexpectedMessageType;
            },
        }
    }

    /// Request a pseudo-terminal
    ///
    /// Must be called before requestShell() or requestExec() if PTY is needed.
    pub fn requestPty(
        self: *Self,
        term: []const u8,
        width_chars: u32,
        height_rows: u32,
        width_pixels: u32,
        height_pixels: u32,
    ) !void {
        // Encode terminal modes (empty for now)
        const modes = try self.allocator.alloc(u8, 1);
        defer self.allocator.free(modes);
        modes[0] = 0; // TTY_OP_END

        // Build type-specific data for pty-req
        const pty_data = try encodePtyRequest(
            self.allocator,
            term,
            width_chars,
            height_rows,
            width_pixels,
            height_pixels,
            modes,
        );
        defer self.allocator.free(pty_data);

        try self.manager.sendRequest(self.stream_id, "pty-req", true, pty_data);

        // Wait for success/failure
        try self.waitForRequestResponse();
    }

    /// Request shell
    ///
    /// Starts an interactive shell on the remote server.
    pub fn requestShell(self: *Self) !void {
        const shell_data = try self.allocator.alloc(u8, 0);
        defer self.allocator.free(shell_data);

        try self.manager.sendRequest(self.stream_id, "shell", true, shell_data);

        // Wait for success/failure
        try self.waitForRequestResponse();
    }

    /// Request command execution
    ///
    /// Executes a single command on the remote server.
    pub fn requestExec(self: *Self, command: []const u8) !void {
        const exec_data = try encodeExecRequest(self.allocator, command);
        defer self.allocator.free(exec_data);

        try self.manager.sendRequest(self.stream_id, "exec", true, exec_data);

        // Wait for success/failure
        try self.waitForRequestResponse();
    }

    /// Request subsystem
    ///
    /// Starts a subsystem like "sftp" on the channel.
    pub fn requestSubsystem(self: *Self, subsystem_name: []const u8) !void {
        const subsystem_data = try encodeSubsystemRequest(self.allocator, subsystem_name);
        defer self.allocator.free(subsystem_data);

        try self.manager.sendRequest(self.stream_id, "subsystem", true, subsystem_data);

        // Wait for success/failure
        try self.waitForRequestResponse();
    }

    /// Wait for request response (success or failure)
    fn waitForRequestResponse(self: *Self) !void {
        var buffer: [4096]u8 = undefined;
        const len = try self.manager.transport.receiveFromStream(self.stream_id, &buffer);
        const data = buffer[0..len];

        if (data.len < 1) {
            return error.InvalidResponse;
        }

        const msg_type = data[0];
        switch (msg_type) {
            99 => { // SSH_MSG_CHANNEL_SUCCESS
                std.log.info("Channel request succeeded", .{});
            },
            100 => { // SSH_MSG_CHANNEL_FAILURE
                std.log.err("Channel request failed", .{});
                return error.ChannelRequestFailed;
            },
            else => {
                std.log.err("Unexpected message type: {}", .{msg_type});
                return error.UnexpectedMessageType;
            },
        }
    }

    /// Send data on the session channel
    pub fn sendData(self: *Self, data: []const u8) !void {
        try self.manager.sendData(self.stream_id, data);
    }

    /// Receive data from the session channel
    ///
    /// Returns the payload data. Caller owns the memory.
    pub fn receiveData(self: *Self) ![]u8 {
        return self.manager.receiveData(self.stream_id);
    }

    /// Send EOF on the channel
    pub fn sendEof(self: *Self) !void {
        try self.manager.sendEof(self.stream_id);
    }

    /// Close the session channel
    pub fn close(self: *Self) !void {
        try self.manager.closeChannel(self.stream_id);
    }

    /// Get the underlying stream ID
    pub fn getStreamId(self: *const Self) u64 {
        return self.stream_id;
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode PTY request type-specific data
fn encodePtyRequest(
    allocator: Allocator,
    term: []const u8,
    width_chars: u32,
    height_rows: u32,
    width_pixels: u32,
    height_pixels: u32,
    modes: []const u8,
) ![]u8 {
    const size = 4 + term.len + // string(TERM)
        4 + // uint32(terminal width, characters)
        4 + // uint32(terminal height, rows)
        4 + // uint32(terminal width, pixels)
        4 + // uint32(terminal height, pixels)
        4 + modes.len; // string(encoded terminal modes)

    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var writer = wire.Writer{ .buffer = buffer };
    try writer.writeString(term);
    try writer.writeUint32(width_chars);
    try writer.writeUint32(height_rows);
    try writer.writeUint32(width_pixels);
    try writer.writeUint32(height_pixels);
    try writer.writeString(modes);

    return buffer;
}

/// Encode exec request type-specific data
fn encodeExecRequest(allocator: Allocator, command: []const u8) ![]u8 {
    const size = 4 + command.len;
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var writer = wire.Writer{ .buffer = buffer };
    try writer.writeString(command);

    return buffer;
}

/// Encode subsystem request type-specific data
fn encodeSubsystemRequest(allocator: Allocator, subsystem_name: []const u8) ![]u8 {
    const size = 4 + subsystem_name.len;
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var writer = wire.Writer{ .buffer = buffer };
    try writer.writeString(subsystem_name);

    return buffer;
}

// ============================================================================
// Server-Side Session Handler
// ============================================================================

/// Server-side session channel handler
pub const SessionServer = struct {
    manager: *ChannelManager,
    allocator: Allocator,

    const Self = @This();

    /// Callback for handling shell requests
    pub const ShellHandler = *const fn (stream_id: u64) anyerror!void;

    /// Callback for handling exec requests
    pub const ExecHandler = *const fn (stream_id: u64, command: []const u8) anyerror!void;

    /// Callback for handling subsystem requests
    pub const SubsystemHandler = *const fn (stream_id: u64, subsystem_name: []const u8) anyerror!void;

    pub fn init(allocator: Allocator, manager: *ChannelManager) Self {
        return Self{
            .manager = manager,
            .allocator = allocator,
        };
    }

    /// Accept incoming session channel
    pub fn acceptSession(self: *Self, stream_id: u64) !void {
        try self.manager.acceptChannel(stream_id);
    }

    /// Handle incoming channel request
    ///
    /// Dispatches to appropriate handler based on request type.
    pub fn handleRequest(
        self: *Self,
        stream_id: u64,
        data: []const u8,
        shell_handler: ?ShellHandler,
        exec_handler: ?ExecHandler,
        subsystem_handler: ?SubsystemHandler,
    ) !void {
        var request_info = try self.manager.handleRequest(stream_id, data);
        defer request_info.deinit(self.allocator);

        std.log.info("Handling channel request: {s}", .{request_info.request.request_type});

        if (std.mem.eql(u8, request_info.request.request_type, "shell")) {
            if (shell_handler) |handler| {
                try handler(stream_id);
                try self.manager.sendSuccess(stream_id);
            } else {
                try self.manager.sendFailure(stream_id);
            }
        } else if (std.mem.eql(u8, request_info.request.request_type, "exec")) {
            if (exec_handler) |handler| {
                // Decode command from type-specific data
                var reader = wire.Reader{ .buffer = request_info.request.type_specific_data };
                const command = try reader.readString(self.allocator);
                defer self.allocator.free(command);

                try handler(stream_id, command);
                try self.manager.sendSuccess(stream_id);
            } else {
                try self.manager.sendFailure(stream_id);
            }
        } else if (std.mem.eql(u8, request_info.request.request_type, "subsystem")) {
            if (subsystem_handler) |handler| {
                // Decode subsystem name from type-specific data
                var reader = wire.Reader{ .buffer = request_info.request.type_specific_data };
                const subsystem_name = try reader.readString(self.allocator);
                defer self.allocator.free(subsystem_name);

                try handler(stream_id, subsystem_name);
                try self.manager.sendSuccess(stream_id);
            } else {
                try self.manager.sendFailure(stream_id);
            }
        } else if (std.mem.eql(u8, request_info.request.request_type, "pty-req")) {
            // PTY requests are typically accepted automatically
            try self.manager.sendSuccess(stream_id);
        } else {
            // Unknown request type
            std.log.warn("Unknown channel request type: {s}", .{request_info.request.request_type});
            try self.manager.sendFailure(stream_id);
        }
    }

    /// Send data to client
    pub fn sendData(self: *Self, stream_id: u64, data: []const u8) !void {
        try self.manager.sendData(stream_id, data);
    }

    /// Receive data from client
    pub fn receiveData(self: *Self, stream_id: u64) ![]u8 {
        return self.manager.receiveData(stream_id);
    }

    /// Send EOF to client
    pub fn sendEof(self: *Self, stream_id: u64) !void {
        try self.manager.sendEof(stream_id);
    }

    /// Close the session
    pub fn close(self: *Self, stream_id: u64) !void {
        try self.manager.closeChannel(stream_id);
    }
};
