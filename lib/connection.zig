const std = @import("std");
const Allocator = std.mem.Allocator;

// Import modules
const kex_exchange = @import("kex/exchange.zig");
const quic_transport = @import("transport/quic_transport.zig");
const constants = @import("common/constants.zig");

/// SSH/QUIC connection configuration
pub const ConnectionConfig = struct {
    /// Server hostname or IP address
    server_address: []const u8,

    /// Server port (default: 22)
    server_port: u16 = 22,

    /// Optional server name indication (SNI)
    server_name: ?[]const u8 = null,

    /// Supported QUIC versions
    quic_versions: []const u32 = &[_]u32{1},

    /// Client QUIC transport parameters
    quic_params: []const u8 = "",

    /// Random number generator
    random: std.Random,
};

/// Server configuration for accepting connections
pub const ServerConfig = struct {
    /// Listen address (e.g., "0.0.0.0", "::")
    listen_address: []const u8,

    /// Listen port (default: 22)
    listen_port: u16 = 22,

    /// Supported QUIC versions
    quic_versions: []const u32 = &[_]u32{1},

    /// Server QUIC transport parameters
    quic_params: []const u8 = "",

    /// Server host key (Ed25519 public key)
    host_key: []const u8,

    /// Server host private key (Ed25519)
    host_private_key: *const [64]u8,

    /// Random number generator
    random: std.Random,
};

/// Active SSH/QUIC client connection
pub const ClientConnection = struct {
    allocator: Allocator,
    transport: quic_transport.QuicTransport,
    kex: kex_exchange.ClientKeyExchange,

    const Self = @This();

    /// Establish a new SSH/QUIC connection to a server
    ///
    /// This performs:
    /// 1. SSH key exchange (SSH_QUIC_INIT/REPLY)
    /// 2. QUIC secret derivation
    /// 3. QUIC connection initialization
    ///
    /// Returns ready-to-use connection
    pub fn connect(allocator: Allocator, config: ConnectionConfig) !Self {
        // Initialize key exchange
        var kex = kex_exchange.ClientKeyExchange.init(allocator, config.random);
        errdefer kex.deinit();

        // Create SSH_QUIC_INIT message
        const server_name = config.server_name orelse config.server_address;
        const init_data = try kex.createInit(
            server_name,
            config.quic_versions,
            config.quic_params,
        );
        defer allocator.free(init_data);

        // TODO: Send init_data over UDP to server
        // For now, this is a placeholder - actual network I/O would go here
        std.log.info("Would send SSH_QUIC_INIT ({} bytes) to {}:{}", .{
            init_data.len,
            config.server_address,
            config.server_port,
        });

        // TODO: Receive SSH_QUIC_REPLY from server
        // For now, simulate with error
        return error.NetworkNotImplemented;

        // When network is implemented, the flow would be:
        // const reply_data = try receiveReply();
        // defer allocator.free(reply_data);
        //
        // const secrets = try kex.processReply(reply_data);
        //
        // var transport = try quic_transport.QuicTransport.init(
        //     allocator,
        //     config.server_address,
        //     config.server_port,
        //     &secrets.client_secret,
        //     &secrets.server_secret,
        //     false, // client mode
        // );
        //
        // return Self{
        //     .allocator = allocator,
        //     .transport = transport,
        //     .kex = kex,
        // };
    }

    pub fn deinit(self: *Self) void {
        self.transport.deinit();
        self.kex.deinit();
    }

    /// Open a new SSH channel (maps to QUIC stream)
    pub fn openChannel(self: *Self) !u64 {
        return self.transport.openStream();
    }

    /// Close a channel
    pub fn closeChannel(self: *Self, channel_id: u64) !void {
        return self.transport.closeStream(channel_id);
    }

    /// Send data on a channel
    pub fn sendData(self: *Self, channel_id: u64, data: []const u8) !void {
        return self.transport.sendOnStream(channel_id, data);
    }

    /// Receive data from a channel
    pub fn receiveData(self: *Self, channel_id: u64, buffer: []u8) !usize {
        return self.transport.receiveFromStream(channel_id, buffer);
    }
};

/// Active SSH/QUIC server connection handler
pub const ServerConnection = struct {
    allocator: Allocator,
    transport: quic_transport.QuicTransport,
    kex: kex_exchange.ServerKeyExchange,

    const Self = @This();

    /// Accept and handle an incoming SSH/QUIC connection
    ///
    /// This performs:
    /// 1. Receive and process SSH_QUIC_INIT
    /// 2. Perform key exchange
    /// 3. Send SSH_QUIC_REPLY
    /// 4. Initialize QUIC connection with derived secrets
    pub fn accept(
        allocator: Allocator,
        config: ServerConfig,
        init_data: []const u8,
    ) !Self {
        // Initialize server key exchange
        var kex = kex_exchange.ServerKeyExchange.init(allocator, config.random);
        errdefer kex.deinit();

        // Process init and create reply
        const result = try kex.processInitAndCreateReply(
            init_data,
            config.quic_versions,
            config.quic_params,
            config.host_key,
            config.host_private_key,
        );
        defer allocator.free(result.reply_data);

        // TODO: Send reply_data back to client over UDP
        std.log.info("Would send SSH_QUIC_REPLY ({} bytes) to client", .{result.reply_data.len});

        // Initialize QUIC transport with derived secrets
        var transport = try quic_transport.QuicTransport.init(
            allocator,
            config.listen_address,
            config.listen_port,
            &result.client_secret,
            &result.server_secret,
            true, // server mode
        );
        errdefer transport.deinit();

        return Self{
            .allocator = allocator,
            .transport = transport,
            .kex = kex,
        };
    }

    pub fn deinit(self: *Self) void {
        self.transport.deinit();
        self.kex.deinit();
    }

    /// Accept a new channel opened by client
    pub fn acceptChannel(self: *Self) !u64 {
        // TODO: Wait for channel open message on next available stream
        _ = self;
        return error.NotImplemented;
    }

    /// Send data on a channel
    pub fn sendData(self: *Self, channel_id: u64, data: []const u8) !void {
        return self.transport.sendOnStream(channel_id, data);
    }

    /// Receive data from a channel
    pub fn receiveData(self: *Self, channel_id: u64, buffer: []u8) !usize {
        return self.transport.receiveFromStream(channel_id, buffer);
    }
};

/// Connection listener for accepting multiple client connections
pub const ConnectionListener = struct {
    allocator: Allocator,
    config: ServerConfig,

    const Self = @This();

    /// Start listening for SSH/QUIC connections
    pub fn listen(allocator: Allocator, config: ServerConfig) !Self {
        std.log.info("SSH/QUIC server listening on {}:{}", .{
            config.listen_address,
            config.listen_port,
        });

        return Self{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
        // Cleanup resources
    }

    /// Accept the next incoming connection
    ///
    /// This blocks until a client connects
    pub fn acceptConnection(self: *Self) !ServerConnection {
        // TODO: Implement actual UDP socket listening
        // For now, return error
        _ = self;
        return error.NetworkNotImplemented;

        // When implemented:
        // const init_data = try receiveInitFromClient();
        // defer self.allocator.free(init_data);
        //
        // return ServerConnection.accept(self.allocator, self.config, init_data);
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a simple client connection (convenience wrapper)
pub fn connectClient(
    allocator: Allocator,
    server_address: []const u8,
    server_port: u16,
    random: std.Random,
) !ClientConnection {
    const config = ConnectionConfig{
        .server_address = server_address,
        .server_port = server_port,
        .random = random,
    };

    return ClientConnection.connect(allocator, config);
}

/// Start a simple server listener (convenience wrapper)
pub fn startServer(
    allocator: Allocator,
    listen_address: []const u8,
    listen_port: u16,
    host_key: []const u8,
    host_private_key: *const [64]u8,
    random: std.Random,
) !ConnectionListener {
    const config = ServerConfig{
        .listen_address = listen_address,
        .listen_port = listen_port,
        .host_key = host_key,
        .host_private_key = host_private_key,
        .random = random,
    };

    return ConnectionListener.listen(allocator, config);
}

// ============================================================================
// Tests
// ============================================================================

test "ServerConnection - accept with init data" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    // Create mock SSH_QUIC_INIT
    var client_kex = kex_exchange.ClientKeyExchange.init(allocator, random);
    defer client_kex.deinit();

    const quic_versions = [_]u32{1};
    const init_data = try client_kex.createInit("localhost", &quic_versions, "client_params");
    defer allocator.free(init_data);

    // Server accepts connection
    var host_private_key: [64]u8 = undefined;
    random.bytes(&host_private_key);

    const config = ServerConfig{
        .listen_address = "127.0.0.1",
        .listen_port = 2222,
        .quic_versions = &quic_versions,
        .quic_params = "server_params",
        .host_key = "ssh-ed25519 AAAA...",
        .host_private_key = &host_private_key,
        .random = random,
    };

    var server_conn = try ServerConnection.accept(allocator, config, init_data);
    defer server_conn.deinit();

    // Verify transport is in SSH mode
    try testing.expect(server_conn.transport.isSshMode());
    try testing.expect(server_conn.transport.isReady());
}

test "ConnectionConfig - default values" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    const config = ConnectionConfig{
        .server_address = "example.com",
        .random = random,
    };

    try testing.expectEqual(@as(u16, 22), config.server_port);
    try testing.expectEqual(@as(?[]const u8, null), config.server_name);
}

test "ServerConfig - initialization" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(99999);
    const random = prng.random();

    var host_private_key: [64]u8 = undefined;
    random.bytes(&host_private_key);

    const config = ServerConfig{
        .listen_address = "0.0.0.0",
        .host_key = "ssh-ed25519 key...",
        .host_private_key = &host_private_key,
        .random = random,
    };

    try testing.expectEqual(@as(u16, 22), config.listen_port);
    try testing.expectEqualStrings("0.0.0.0", config.listen_address);
}
