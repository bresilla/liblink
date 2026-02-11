const std = @import("std");
const Allocator = std.mem.Allocator;
const zquic = @import("zquic");

/// QUIC transport with SSH secret injection
/// Uses forked zquic library with SshQuic module for SSH-derived secrets

pub const QuicTransport = struct {
    allocator: Allocator,
    ssh_quic_ctx: zquic.SshQuic.SshQuicContext,
    is_server: bool,

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
    ) !QuicTransport {
        _ = address;
        _ = port;

        // Create SSH secrets for QUIC
        const secrets = zquic.SshQuic.SshQuicSecrets.init(client_secret.*, server_secret.*);

        // Initialize QUIC context with SSH secrets (bypasses TLS handshake)
        const ssh_quic_ctx = try zquic.SshQuic.SshQuicContext.initWithSshSecrets(
            allocator,
            is_server,
            secrets,
        );

        return QuicTransport{
            .allocator = allocator,
            .ssh_quic_ctx = ssh_quic_ctx,
            .is_server = is_server,
        };
    }

    pub fn deinit(self: *QuicTransport) void {
        self.ssh_quic_ctx.deinit();
    }

    /// Check if connection is ready to send/receive data
    pub fn isReady(self: *const QuicTransport) bool {
        return self.ssh_quic_ctx.isReady();
    }

    /// Check if using SSH mode (true for SSH/QUIC, false for normal TLS)
    pub fn isSshMode(self: *const QuicTransport) bool {
        return self.ssh_quic_ctx.isSshMode();
    }

    /// Open a new bidirectional stream
    pub fn openStream(self: *QuicTransport) !u64 {
        _ = self;
        // TODO: Call zquic API to open bidirectional stream
        // Return stream ID

        return error.NotImplemented;
    }

    /// Close a stream
    pub fn closeStream(self: *QuicTransport, stream_id: u64) !void {
        _ = self;
        _ = stream_id;
        // TODO: Close stream using zquic API
        return error.NotImplemented;
    }

    /// Send data on a stream
    pub fn sendOnStream(self: *QuicTransport, stream_id: u64, data: []const u8) !void {
        _ = self;
        _ = stream_id;
        _ = data;
        // TODO: Send data using zquic stream write
        return error.NotImplemented;
    }

    /// Receive data from a stream
    pub fn receiveFromStream(self: *QuicTransport, stream_id: u64, buffer: []u8) !usize {
        _ = self;
        _ = stream_id;
        _ = buffer;
        // TODO: Receive data using zquic stream read
        // Return number of bytes read
        return error.NotImplemented;
    }

    /// Send stream FIN (end of stream)
    pub fn sendStreamFin(self: *QuicTransport, stream_id: u64) !void {
        _ = self;
        _ = stream_id;
        // TODO: Send FIN on stream
        return error.NotImplemented;
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
