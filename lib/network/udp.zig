const std = @import("std");
const Allocator = std.mem.Allocator;
const net = std.net;

/// UDP socket for SSH/QUIC initial key exchange
///
/// Per SPEC.md: SSH_QUIC_INIT and SSH_QUIC_REPLY are exchanged as UDP datagrams
/// before QUIC connection is established.

pub const UdpSocket = struct {
    socket: std.posix.socket_t,
    address: net.Address,
    allocator: Allocator,
    is_server: bool,

    const Self = @This();

    /// Create and bind UDP socket for client
    ///
    /// The socket will be bound to an ephemeral port and ready to send to server
    pub fn initClient(
        allocator: Allocator,
        server_address: []const u8,
        server_port: u16,
    ) !Self {
        // Parse server address
        const address = try net.Address.parseIp4(server_address, server_port);

        // Create UDP socket
        const socket = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        return Self{
            .socket = socket,
            .address = address,
            .allocator = allocator,
            .is_server = false,
        };
    }

    /// Create and bind UDP socket for server
    ///
    /// The socket will be bound to the specified address and port, ready to accept
    pub fn initServer(
        allocator: Allocator,
        listen_address: []const u8,
        listen_port: u16,
    ) !Self {
        // Parse listen address
        const address = try net.Address.parseIp4(listen_address, listen_port);

        // Create UDP socket
        const socket = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        // Bind to address
        try std.posix.bind(socket, &address.any, address.getOsSockLen());

        return Self{
            .socket = socket,
            .address = address,
            .allocator = allocator,
            .is_server = true,
        };
    }

    pub fn deinit(self: *Self) void {
        std.posix.close(self.socket);
    }

    /// Send UDP datagram to remote address
    ///
    /// Used by client to send SSH_QUIC_INIT to server
    pub fn send(self: *Self, data: []const u8) !void {
        const bytes_sent = try std.posix.sendto(
            self.socket,
            data,
            0,
            &self.address.any,
            self.address.getOsSockLen(),
        );

        if (bytes_sent != data.len) {
            return error.PartialSend;
        }
    }

    /// Receive UDP datagram (blocking)
    ///
    /// Returns the received data. Caller owns the memory.
    /// Used by client to receive SSH_QUIC_REPLY from server
    pub fn receive(self: *Self, max_size: usize) ![]u8 {
        const buffer = try self.allocator.alloc(u8, max_size);
        errdefer self.allocator.free(buffer);

        const bytes_received = try std.posix.recv(self.socket, buffer, 0);

        // Resize buffer to actual received size
        if (bytes_received < max_size) {
            const resized = try self.allocator.realloc(buffer, bytes_received);
            return resized;
        }

        return buffer;
    }

    /// Receive UDP datagram with timeout (non-blocking)
    ///
    /// Returns the received data or null if timeout expires
    pub fn receiveWithTimeout(
        self: *Self,
        max_size: usize,
        timeout_ms: u64,
    ) !?[]u8 {
        // Set socket timeout
        const timeout = std.posix.timeval{
            .tv_sec = @intCast(timeout_ms / 1000),
            .tv_usec = @intCast((timeout_ms % 1000) * 1000),
        };

        try std.posix.setsockopt(
            self.socket,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );

        // Try to receive
        return self.receive(max_size) catch |err| {
            if (err == error.WouldBlock) {
                return null;
            }
            return err;
        };
    }

    /// Receive from any client (server only)
    ///
    /// Returns the received data and the sender's address
    pub fn receiveFrom(self: *Self, max_size: usize) !struct {
        data: []u8,
        sender: net.Address,
    } {
        const buffer = try self.allocator.alloc(u8, max_size);
        errdefer self.allocator.free(buffer);

        var sender_addr: std.posix.sockaddr = undefined;
        var sender_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const bytes_received = try std.posix.recvfrom(
            self.socket,
            buffer,
            0,
            &sender_addr,
            &sender_len,
        );

        // Resize buffer
        const data = try self.allocator.realloc(buffer, bytes_received);

        // Convert sockaddr to net.Address
        const sender = net.Address.initPosix(@alignCast(&sender_addr));

        return .{
            .data = data,
            .sender = sender,
        };
    }

    /// Send to specific address (server only)
    ///
    /// Used by server to send SSH_QUIC_REPLY back to client
    pub fn sendTo(self: *Self, data: []const u8, destination: net.Address) !void {
        const bytes_sent = try std.posix.sendto(
            self.socket,
            data,
            0,
            &destination.any,
            destination.getOsSockLen(),
        );

        if (bytes_sent != data.len) {
            return error.PartialSend;
        }
    }
};

/// SSH/QUIC key exchange over UDP
///
/// Handles the initial SSH_QUIC_INIT/REPLY exchange before QUIC is initialized
pub const KeyExchangeTransport = struct {
    socket: UdpSocket,
    allocator: Allocator,

    const Self = @This();

    /// Initialize client key exchange transport
    pub fn initClient(
        allocator: Allocator,
        server_address: []const u8,
        server_port: u16,
    ) !Self {
        const socket = try UdpSocket.initClient(allocator, server_address, server_port);

        return Self{
            .socket = socket,
            .allocator = allocator,
        };
    }

    /// Initialize server key exchange transport
    pub fn initServer(
        allocator: Allocator,
        listen_address: []const u8,
        listen_port: u16,
    ) !Self {
        const socket = try UdpSocket.initServer(allocator, listen_address, listen_port);

        return Self{
            .socket = socket,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.socket.deinit();
    }

    /// Send SSH_QUIC_INIT (client)
    pub fn sendInit(self: *Self, init_data: []const u8) !void {
        try self.socket.send(init_data);

        std.log.info("Sent SSH_QUIC_INIT ({} bytes)", .{init_data.len});
    }

    /// Receive SSH_QUIC_REPLY (client)
    ///
    /// Blocks until reply is received or timeout expires
    /// Returns reply data. Caller owns the memory.
    pub fn receiveReply(self: *Self, timeout_ms: u64) ![]u8 {
        // Max SSH_QUIC_REPLY size (conservatively 64KB)
        const max_size = 65536;

        const data = (try self.socket.receiveWithTimeout(max_size, timeout_ms)) orelse
            return error.ReceiveTimeout;

        std.log.info("Received SSH_QUIC_REPLY ({} bytes)", .{data.len});

        return data;
    }

    /// Receive SSH_QUIC_INIT (server)
    ///
    /// Blocks until init is received from a client
    /// Returns init data and client address. Caller owns init data memory.
    pub fn receiveInit(self: *Self) !struct {
        init_data: []u8,
        client_address: net.Address,
    } {
        // Max SSH_QUIC_INIT size (typically 1200-1500 bytes per spec)
        const max_size = 2048;

        const result = try self.socket.receiveFrom(max_size);

        std.log.info("Received SSH_QUIC_INIT from {} ({} bytes)", .{
            result.sender,
            result.data.len,
        });

        return .{
            .init_data = result.data,
            .client_address = result.sender,
        };
    }

    /// Send SSH_QUIC_REPLY (server)
    pub fn sendReply(self: *Self, reply_data: []const u8, client_address: net.Address) !void {
        try self.socket.sendTo(reply_data, client_address);

        std.log.info("Sent SSH_QUIC_REPLY to {} ({} bytes)", .{
            client_address,
            reply_data.len,
        });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "UdpSocket - client initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Try to create client socket (may fail if network unavailable)
    const socket = UdpSocket.initClient(allocator, "127.0.0.1", 2222) catch |err| {
        std.debug.print("Skipping test (network unavailable): {}\n", .{err});
        return error.SkipZigTest;
    };
    defer socket.deinit();
}

test "KeyExchangeTransport - initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Try to create transport (may fail if network unavailable)
    var transport = KeyExchangeTransport.initClient(allocator, "127.0.0.1", 2222) catch |err| {
        std.debug.print("Skipping test (network unavailable): {}\n", .{err});
        return error.SkipZigTest;
    };
    defer transport.deinit();

    try testing.expect(transport.allocator == allocator);
}
