const std = @import("std");
const Allocator = std.mem.Allocator;
const zquic = @import("zquic");

/// QUIC transport with SSH secret injection
/// Integrates SSH key exchange with zquic QUIC implementation

pub const QuicTransport = struct {
    allocator: Allocator,
    connection: *zquic.core.Connection.SuperConnection,
    ssh_quic_ctx: zquic.core.SshQuic.SshQuicContext,
    is_server: bool,

    const Self = @This();

    /// Initialize QUIC transport with SSH-derived secrets
    ///
    /// Per SPEC.md: After SSH key exchange, we derive:
    /// - client_secret = HMAC-SHA256("ssh/quic client", mpint(K) || string(H))
    /// - server_secret = HMAC-SHA256("ssh/quic server", mpint(K) || string(H))
    ///
    /// These secrets are used to initialize QUIC in "post-handshake" state,
    /// bypassing the TLS 1.3 handshake that zquic normally expects.
    pub fn init(
        allocator: Allocator,
        address: []const u8,
        port: u16,
        client_secret: *const [32]u8,
        server_secret: *const [32]u8,
        is_server: bool,
    ) !Self {
        _ = address;
        _ = port;

        // Create SSH secrets for QUIC
        const secrets = zquic.core.SshQuic.SshQuicSecrets.init(client_secret.*, server_secret.*);

        // Initialize QUIC context with SSH secrets (bypasses TLS handshake)
        var ssh_quic_ctx = try zquic.core.SshQuic.SshQuicContext.initWithSshSecrets(
            allocator,
            is_server,
            secrets,
        );
        errdefer ssh_quic_ctx.deinit();

        // Create QUIC connection with SSH crypto
        const role: zquic.core.Connection.Role = if (is_server) .server else .client;
        const params = zquic.core.Connection.ConnectionParams{};

        const connection = try allocator.create(zquic.core.Connection.SuperConnection);
        errdefer allocator.destroy(connection);

        connection.* = try zquic.core.Connection.SuperConnection.init(allocator, role, params);
        errdefer connection.deinit();

        // Mark connection as established since SSH key exchange is done
        connection.state = .established;

        return Self{
            .allocator = allocator,
            .connection = connection,
            .ssh_quic_ctx = ssh_quic_ctx,
            .is_server = is_server,
        };
    }

    pub fn deinit(self: *Self) void {
        self.connection.deinit();
        self.allocator.destroy(self.connection);
        self.ssh_quic_ctx.deinit();
    }

    /// Check if connection is ready to send/receive data
    pub fn isReady(self: *const Self) bool {
        return self.ssh_quic_ctx.isReady() and self.connection.state == .established;
    }

    /// Check if using SSH mode (true for SSH/QUIC, false for normal TLS)
    pub fn isSshMode(self: *const Self) bool {
        return self.ssh_quic_ctx.isSshMode();
    }

    /// Open a new bidirectional stream
    ///
    /// Per SPEC.md: SSH channels map to QUIC streams
    /// - Client streams: 0, 4, 8, 12... (stream_id % 4 == 0)
    /// - Server streams: 1, 5, 9, 13... (stream_id % 4 == 1)
    pub fn openStream(self: *Self) !u64 {
        const stream_id = self.connection.next_stream_id;

        // Allocate and create stream
        const stream = try self.allocator.create(zquic.core.Stream.SuperStream);
        errdefer self.allocator.destroy(stream);

        const stream_type: zquic.core.Stream.StreamType = if (self.is_server)
            .server_bidirectional
        else
            .client_bidirectional;

        stream.* = try zquic.core.Stream.SuperStream.init(
            self.allocator,
            stream_id,
            stream_type,
        );

        // Add to connection's stream map
        try self.connection.streams.put(self.allocator, stream_id, stream);

        // Increment next stream ID (bidirectional streams increment by 4)
        self.connection.next_stream_id += 4;

        return stream_id;
    }

    /// Close a stream
    pub fn closeStream(self: *Self, stream_id: u64) !void {
        if (self.connection.streams.get(stream_id)) |stream| {
            stream.state.store(.closed, .release);
            // Note: Actual stream cleanup happens in connection.deinit()
        } else {
            return error.StreamNotFound;
        }
    }

    /// Send data on a stream
    pub fn sendOnStream(self: *Self, stream_id: u64, data: []const u8) !void {
        const stream = self.connection.streams.get(stream_id) orelse return error.StreamNotFound;

        // Write data to stream buffer
        _ = try stream.write(data, false);

        // Update connection stats
        self.connection.stats.bytes_sent += data.len;
    }

    /// Receive data from a stream
    pub fn receiveFromStream(self: *Self, stream_id: u64, buffer: []u8) !usize {
        const stream = self.connection.streams.get(stream_id) orelse return error.StreamNotFound;

        // Read data from stream buffer
        const bytes_read = try stream.read(buffer);

        // Update connection stats
        self.connection.stats.bytes_received += bytes_read;

        return bytes_read;
    }

    /// Send stream FIN (end of stream)
    pub fn sendStreamFin(self: *Self, stream_id: u64) !void {
        const stream = self.connection.streams.get(stream_id) orelse return error.StreamNotFound;

        // Mark stream as half-closed local
        stream.state.store(.half_closed_local, .release);

        // Write empty data with FIN flag
        _ = try stream.write(&[_]u8{}, true);
    }
};

test "QuicTransport - SSH secret injection" {
    const allocator = std.testing.allocator;

    // Simulate SSH-derived secrets
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;

    var transport = try QuicTransport.init(
        allocator,
        "127.0.0.1",
        4433,
        &client_secret,
        &server_secret,
        false, // client mode
    );
    defer transport.deinit();

    // Verify SSH mode is active
    try std.testing.expect(transport.isSshMode());

    // Verify connection is ready (handshake bypassed)
    try std.testing.expect(transport.isReady());
}

test "QuicTransport - server mode" {
    const allocator = std.testing.allocator;

    const client_secret = [_]u8{0xCC} ** 32;
    const server_secret = [_]u8{0xDD} ** 32;

    var transport = try QuicTransport.init(
        allocator,
        "0.0.0.0",
        4433,
        &client_secret,
        &server_secret,
        true, // server mode
    );
    defer transport.deinit();

    try std.testing.expect(transport.isSshMode());
    try std.testing.expect(transport.isReady());
    try std.testing.expect(transport.is_server);
}
