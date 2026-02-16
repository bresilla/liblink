const std = @import("std");
const Allocator = std.mem.Allocator;
const quic_transport = @import("../network/quic_transport.zig");
const channel_protocol = @import("../protocol/channel.zig");

/// Channel Manager
///
/// Manages SSH channels mapped to QUIC streams.
/// Handles channel lifecycle, type dispatch, and request routing.
pub const ChannelManager = struct {
    allocator: Allocator,
    transport: *quic_transport.QuicTransport,
    channels: std.AutoHashMap(u64, *ChannelInfo),
    next_client_stream_id: u64, // For client-initiated streams (4, 8, 12, ...)

    const Self = @This();

    /// Channel information
    pub const ChannelInfo = struct {
        stream_id: u64,
        channel_type: []const u8,
        state: channel_protocol.ChannelState,
        allocator: Allocator,

        pub fn deinit(self: *ChannelInfo) void {
            self.allocator.free(self.channel_type);
        }
    };

    pub fn init(allocator: Allocator, transport: *quic_transport.QuicTransport, is_server: bool) Self {
        return Self{
            .allocator = allocator,
            .transport = transport,
            .channels = std.AutoHashMap(u64, *ChannelInfo).init(allocator),
            .next_client_stream_id = if (is_server) 5 else 4, // Server uses 5, 9, 13..., client uses 4, 8, 12...
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.channels.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.channels.deinit();
    }

    /// Open a new channel (client-side)
    ///
    /// Opens a bidirectional QUIC stream and sends CHANNEL_OPEN message.
    /// Returns the stream ID (channel ID).
    pub fn openChannel(
        self: *Self,
        channel_type: []const u8,
        initial_window_size: u32,
        maximum_packet_size: u32,
        type_specific_data: []const u8,
    ) !u64 {
        // Open the QUIC stream and use its assigned ID
        const stream_id = try self.transport.openStream();
        self.next_client_stream_id = stream_id + 4; // Update to next expected stream

        // Create channel info
        const info = try self.allocator.create(ChannelInfo);
        errdefer self.allocator.destroy(info);

        info.* = ChannelInfo{
            .stream_id = stream_id,
            .channel_type = try self.allocator.dupe(u8, channel_type),
            .state = .opening,
            .allocator = self.allocator,
        };
        errdefer info.deinit();

        try self.channels.put(stream_id, info);

        // Send CHANNEL_OPEN message
        const open_msg = channel_protocol.ChannelOpen{
            .channel_type = channel_type,
            .sender_channel = @intCast(stream_id), // Use stream ID as channel ID
            .initial_window_size = initial_window_size,
            .maximum_packet_size = maximum_packet_size,
            .type_specific_data = type_specific_data,
        };

        const encoded = try open_msg.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);

        std.log.info("Opened channel type='{s}' on stream {}", .{ channel_type, stream_id });

        return stream_id;
    }

    /// Accept incoming channel open (server-side)
    ///
    /// Reads CHANNEL_OPEN from a stream and confirms or rejects it.
    pub fn acceptChannel(self: *Self, stream_id: u64) !void {
        // Receive CHANNEL_OPEN message
        var buffer: [4096]u8 = undefined;
        const len = try self.transport.receiveFromStream(stream_id, &buffer);
        const data = buffer[0..len];

        var open_msg = try channel_protocol.ChannelOpen.decode(self.allocator, data);
        defer open_msg.deinit(self.allocator);

        std.log.info("Received CHANNEL_OPEN type='{s}' on stream {}", .{
            open_msg.channel_type,
            stream_id,
        });

        std.log.debug("DEBUG: About to create ChannelInfo", .{});
        // Create channel info
        const info = try self.allocator.create(ChannelInfo);
        errdefer self.allocator.destroy(info);

        std.log.debug("DEBUG: About to dupe channel_type: {s}", .{open_msg.channel_type});
        const channel_type_copy = try self.allocator.dupe(u8, open_msg.channel_type);
        errdefer self.allocator.free(channel_type_copy);

        std.log.debug("DEBUG: Setting ChannelInfo fields", .{});
        info.* = ChannelInfo{
            .stream_id = stream_id,
            .channel_type = channel_type_copy,
            .state = .open, // Accepting means it's open
            .allocator = self.allocator,
        };
        errdefer info.deinit();

        std.log.debug("DEBUG: About to put in channels map", .{});
        try self.channels.put(stream_id, info);

        std.log.debug("DEBUG: Creating CHANNEL_OPEN_CONFIRMATION", .{});
        // Send CHANNEL_OPEN_CONFIRMATION
        const confirm_msg = channel_protocol.ChannelOpenConfirmation{
            .sender_channel = @intCast(stream_id),
            .initial_window_size = open_msg.initial_window_size,
            .maximum_packet_size = open_msg.maximum_packet_size,
            .type_specific_data = "",
        };

        std.log.debug("DEBUG: Encoding confirmation message", .{});
        const encoded = try confirm_msg.encode(self.allocator);
        defer self.allocator.free(encoded);

        std.log.debug("DEBUG: Sending confirmation on stream {}", .{stream_id});
        try self.transport.sendOnStream(stream_id, encoded);

        std.log.debug("DEBUG: acceptChannel completed successfully", .{});
    }

    /// Process CHANNEL_OPEN_CONFIRMATION (client-side)
    pub fn handleOpenConfirmation(self: *Self, stream_id: u64, data: []const u8) !void {
        var confirm_msg = try channel_protocol.ChannelOpenConfirmation.decode(self.allocator, data);
        defer confirm_msg.deinit(self.allocator);

        if (self.channels.get(stream_id)) |info| {
            info.state = .open;
            std.log.info("Channel {} confirmed and open", .{stream_id});
        } else {
            return error.UnknownChannel;
        }
    }

    /// Process CHANNEL_OPEN_FAILURE (client-side)
    pub fn handleOpenFailure(self: *Self, stream_id: u64, data: []const u8) !void {
        var failure_msg = try channel_protocol.ChannelOpenFailure.decode(self.allocator, data);
        defer failure_msg.deinit(self.allocator);

        std.log.err("Channel {} open failed: code={}, desc={s}", .{
            stream_id,
            failure_msg.reason_code,
            failure_msg.description,
        });

        if (self.channels.get(stream_id)) |info| {
            info.state = .failed;
        }
    }

    /// Send channel request (shell, exec, subsystem, etc.)
    pub fn sendRequest(
        self: *Self,
        stream_id: u64,
        request_type: []const u8,
        want_reply: bool,
        type_specific_data: []const u8,
    ) !void {
        const request_msg = channel_protocol.ChannelRequest{
            .request_type = request_type,
            .want_reply = want_reply,
            .type_specific_data = type_specific_data,
        };

        const encoded = try request_msg.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);

        std.log.info("Sent CHANNEL_REQUEST type='{s}' on stream {}", .{
            request_type,
            stream_id,
        });
    }

    /// Handle incoming channel request (server-side)
    pub fn handleRequest(self: *Self, stream_id: u64, data: []const u8) !ChannelRequestInfo {
        const request_msg = try channel_protocol.ChannelRequest.decode(self.allocator, data);
        // Caller is responsible for calling deinit on returned ChannelRequestInfo

        return ChannelRequestInfo{
            .stream_id = stream_id,
            .request = request_msg,
        };
    }

    /// Send channel request success
    pub fn sendSuccess(self: *Self, stream_id: u64) !void {
        const encoded = try channel_protocol.ChannelSuccess.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);
    }

    /// Send channel request failure
    pub fn sendFailure(self: *Self, stream_id: u64) !void {
        const encoded = try channel_protocol.ChannelFailure.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);
    }

    /// Send data on channel
    pub fn sendData(self: *Self, stream_id: u64, data: []const u8) !void {
        const data_msg = channel_protocol.ChannelData{
            .data = data,
        };

        const encoded = try data_msg.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);
    }

    /// Receive data from channel
    ///
    /// Reads and decodes CHANNEL_DATA message from stream.
    /// Returns the payload data. Caller owns the memory.
    pub fn receiveData(self: *Self, stream_id: u64) ![]u8 {
        // Use a large buffer to accumulate the complete message
        var buffer: [65536]u8 = undefined;
        var total_received: usize = 0;

        // First, we need at least 5 bytes for the message header (type + length)
        while (total_received < 5) {
            const len = try self.transport.receiveFromStream(stream_id, buffer[total_received..]);
            if (len == 0) {
                if (total_received == 0) return error.NoData;
                // Poll for more data
                self.transport.poll(100) catch {};
                continue;
            }
            total_received += len;
        }

        // Parse message type
        if (buffer[0] != 94) { // SSH_MSG_CHANNEL_DATA
            std.log.err("receiveData: unexpected message type {}, expected 94 (CHANNEL_DATA)", .{buffer[0]});
            return error.InvalidMessageType;
        }

        // Parse data length (4 bytes, big-endian)
        const data_len = std.mem.readInt(u32, buffer[1..5], .big);
        const total_msg_len = 5 + data_len; // header (5 bytes) + data

        // std.log.debug("receiveData: message claims {} bytes of data, total message = {} bytes", .{ data_len, total_msg_len });

        // Read the rest of the message, polling for more data if needed
        var poll_attempts: u32 = 0;
        while (total_received < total_msg_len) {
            const len = try self.transport.receiveFromStream(stream_id, buffer[total_received..]);
            if (len == 0) {
                // No more data in buffer, poll for more packets
                poll_attempts += 1;
                if (poll_attempts > 100) { // 10 seconds timeout
                    std.log.err("receiveData: timeout waiting for complete message, got {} bytes, expected {}", .{ total_received, total_msg_len });
                    return error.IncompleteMessage;
                }
                self.transport.poll(100) catch {}; // 100ms poll
                continue;
            }
            total_received += len;
            poll_attempts = 0; // Reset timeout counter when we get data
            // std.log.debug("receiveData: read {} more bytes, total now {}/{}", .{ len, total_received, total_msg_len });
        }

        // std.log.debug("receiveData: complete message received, {} bytes total", .{total_received});

        // Now decode the complete message
        const data_msg = try channel_protocol.ChannelData.decode(self.allocator, buffer[0..total_received]);
        // Don't defer deinit - caller owns the data

        return @constCast(data_msg.data);
    }

    /// Send EOF on channel
    pub fn sendEof(self: *Self, stream_id: u64) !void {
        const encoded = try channel_protocol.ChannelEof.encode(self.allocator);
        defer self.allocator.free(encoded);

        try self.transport.sendOnStream(stream_id, encoded);

        if (self.channels.get(stream_id)) |info| {
            info.state = .eof_sent;
        }
    }

    /// Close a channel
    ///
    /// In SSH/QUIC, this closes the underlying QUIC stream with FIN.
    pub fn closeChannel(self: *Self, stream_id: u64) !void {
        try self.transport.closeStream(stream_id);

        if (self.channels.getPtr(stream_id)) |info| {
            info.*.state = .closed;
        }

        std.log.info("Closed channel {}", .{stream_id});
    }

    /// Get channel state
    pub fn getChannelState(self: *Self, stream_id: u64) ?channel_protocol.ChannelState {
        if (self.channels.get(stream_id)) |info| {
            return info.state;
        }
        return null;
    }

    /// Check if channel is open
    pub fn isChannelOpen(self: *Self, stream_id: u64) bool {
        if (self.channels.get(stream_id)) |info| {
            return info.state == .open;
        }
        return false;
    }

    /// Get the next expected client stream ID (server-side)
    ///
    /// For servers accepting connections from clients, client streams
    /// are bidirectional streams with IDs 4, 8, 12, 16, etc.
    pub fn getNextClientStream(self: *const Self) u64 {
        // Find the highest client stream ID and return next one
        // Client streams: 4, 8, 12, 16, ...
        var max_client_stream: u64 = 0;
        var iter = self.channels.iterator();
        while (iter.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            // Client bidirectional streams have IDs 0x00, 0x04, 0x08, ... (client-initiated)
            if (stream_id % 4 == 0 and stream_id > 0) {
                if (stream_id > max_client_stream) {
                    max_client_stream = stream_id;
                }
            }
        }
        return if (max_client_stream == 0) 4 else max_client_stream + 4;
    }

    /// Register a channel with a given type (for manual channel setup)
    pub fn registerChannel(self: *Self, stream_id: u64, channel_type: []const u8) !void {
        const info = try self.allocator.create(ChannelInfo);
        errdefer self.allocator.destroy(info);

        info.* = ChannelInfo{
            .stream_id = stream_id,
            .channel_type = try self.allocator.dupe(u8, channel_type),
            .state = .open,
            .allocator = self.allocator,
        };
        errdefer info.deinit();

        try self.channels.put(stream_id, info);
    }
};

/// Information about a received channel request
pub const ChannelRequestInfo = struct {
    stream_id: u64,
    request: channel_protocol.ChannelRequest,

    pub fn deinit(self: *ChannelRequestInfo, allocator: Allocator) void {
        self.request.deinit(allocator);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ChannelManager - init and deinit" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a mock transport (we can't actually initialize it without full stack)
    // This test just verifies the manager structure
    var manager = ChannelManager.init(allocator, undefined, false);
    defer manager.deinit();

    try testing.expectEqual(@as(u64, 4), manager.next_client_stream_id);
}

test "ChannelManager - server stream IDs" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var manager = ChannelManager.init(allocator, undefined, true);
    defer manager.deinit();

    try testing.expectEqual(@as(u64, 5), manager.next_client_stream_id);
}
