const std = @import("std");
const Allocator = std.mem.Allocator;

// Import modules
const kex_exchange = @import("kex/exchange.zig");
const quic_transport = @import("transport/quic_transport.zig");
const udp = @import("network/udp.zig");
const constants = @import("common/constants.zig");
const auth = @import("auth/auth.zig");
const channels = @import("channels/channels.zig");
const sftp = @import("sftp/sftp.zig");

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
    channel_manager: channels.ChannelManager,

    const Self = @This();

    /// Establish a new SSH/QUIC connection to a server
    ///
    /// This performs:
    /// 1. SSH key exchange (SSH_QUIC_INIT/REPLY) over UDP
    /// 2. QUIC secret derivation from SSH exchange
    /// 3. QUIC connection initialization with SSH secrets
    ///
    /// Returns ready-to-use connection
    pub fn connect(allocator: Allocator, config: ConnectionConfig) !Self {
        std.log.info("Connecting to {}:{}...", .{ config.server_address, config.server_port });

        // Initialize UDP transport for key exchange
        var udp_transport = try udp.KeyExchangeTransport.initClient(
            allocator,
            config.server_address,
            config.server_port,
        );
        defer udp_transport.deinit();

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

        // Send SSH_QUIC_INIT over UDP
        try udp_transport.sendInit(init_data);

        // Receive SSH_QUIC_REPLY (with 10 second timeout)
        const reply_data = try udp_transport.receiveReply(10000);
        defer allocator.free(reply_data);

        // Process reply and derive QUIC secrets
        std.log.info("Processing SSH_QUIC_REPLY...", .{});
        const secrets = try kex.processReply(reply_data);

        // Initialize QUIC transport with SSH-derived secrets
        std.log.info("Initializing QUIC connection...", .{});
        var transport = try quic_transport.QuicTransport.init(
            allocator,
            config.server_address,
            config.server_port,
            &secrets.client_secret,
            &secrets.server_secret,
            false, // client mode
        );
        errdefer transport.deinit();

        std.log.info("SSH/QUIC connection established", .{});

        // Initialize channel manager
        const channel_manager = channels.ChannelManager.init(allocator, &transport, false);

        return Self{
            .allocator = allocator,
            .transport = transport,
            .kex = kex,
            .channel_manager = channel_manager,
        };
    }

    pub fn deinit(self: *Self) void {
        self.channel_manager.deinit();
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

    /// Authenticate with password
    ///
    /// Uses stream 0 for authentication protocol.
    /// Returns true on success, false on failure.
    pub fn authenticatePassword(self: *Self, username: []const u8, password: []const u8) !bool {
        var auth_client = auth.AuthClient.init(self.allocator, username);

        // Create authentication request
        const request_data = try auth_client.authenticatePassword(password);
        defer self.allocator.free(request_data);

        // Send on stream 0 (authentication stream)
        try self.transport.sendOnStream(0, request_data);

        // Receive response
        var response_buffer: [4096]u8 = undefined;
        const response_len = try self.transport.receiveFromStream(0, &response_buffer);
        const response_data = response_buffer[0..response_len];

        // Process response
        var result = try auth_client.processResponse(response_data);
        defer result.deinit(self.allocator);

        return switch (result) {
            .success => true,
            .failure => false,
            .banner => |b| {
                std.log.info("Server banner: {s}", .{b.message});
                return false; // Banner doesn't complete auth, wait for next response
            },
        };
    }

    /// Authenticate with public key
    ///
    /// First queries if the key is acceptable, then sends signed request.
    /// Returns true on success, false on failure.
    pub fn authenticatePublicKey(
        self: *Self,
        username: []const u8,
        algorithm_name: []const u8,
        public_key_blob: []const u8,
        private_key: *const [64]u8,
    ) !bool {
        var auth_client = auth.AuthClient.init(self.allocator, username);

        // Get exchange hash (session identifier) from key exchange
        const exchange_hash = self.kex.getExchangeHash();

        // First try: query without signature
        {
            const query_data = try auth_client.authenticatePublicKey(
                algorithm_name,
                public_key_blob,
                null, // no signature
                exchange_hash,
            );
            defer self.allocator.free(query_data);

            try self.transport.sendOnStream(0, query_data);

            var response_buffer: [4096]u8 = undefined;
            const response_len = try self.transport.receiveFromStream(0, &response_buffer);
            const response_data = response_buffer[0..response_len];

            var result = try auth_client.processResponse(response_data);
            defer result.deinit(self.allocator);

            // If server rejects the key, don't continue
            if (result == .failure) {
                return false;
            }
        }

        // Second try: with signature
        {
            const auth_data = try auth_client.authenticatePublicKey(
                algorithm_name,
                public_key_blob,
                private_key,
                exchange_hash,
            );
            defer self.allocator.free(auth_data);

            try self.transport.sendOnStream(0, auth_data);

            var response_buffer: [4096]u8 = undefined;
            const response_len = try self.transport.receiveFromStream(0, &response_buffer);
            const response_data = response_buffer[0..response_len];

            var result = try auth_client.processResponse(response_data);
            defer result.deinit(self.allocator);

            return result == .success;
        }
    }

    /// Query available authentication methods
    pub fn queryAuthMethods(self: *Self, username: []const u8) ![]const []const u8 {
        var auth_client = auth.AuthClient.init(self.allocator, username);

        const none_data = try auth_client.authenticateNone();
        defer self.allocator.free(none_data);

        try self.transport.sendOnStream(0, none_data);

        var response_buffer: [4096]u8 = undefined;
        const response_len = try self.transport.receiveFromStream(0, &response_buffer);
        const response_data = response_buffer[0..response_len];

        const result = try auth_client.processResponse(response_data);
        // Don't defer deinit here - caller owns the methods list

        return switch (result) {
            .failure => |f| f.methods, // Return available methods
            else => &[_][]const u8{}, // Unexpected success or banner
        };
    }

    /// Open a new session channel
    ///
    /// Returns a SessionChannel for shell, exec, or subsystem requests.
    pub fn openSession(self: *Self) !channels.SessionChannel {
        return channels.SessionChannel.open(self.allocator, &self.channel_manager);
    }

    /// Request shell on a session channel (convenience method)
    ///
    /// Opens a session channel, requests a shell, and returns the channel.
    pub fn requestShell(self: *Self) !channels.SessionChannel {
        var session = try self.openSession();
        errdefer session.close() catch {};

        try session.waitForConfirmation();
        try session.requestShell();

        return session;
    }

    /// Execute a command on a session channel (convenience method)
    ///
    /// Opens a session channel, executes the command, and returns the channel.
    pub fn requestExec(self: *Self, command: []const u8) !channels.SessionChannel {
        var session = try self.openSession();
        errdefer session.close() catch {};

        try session.waitForConfirmation();
        try session.requestExec(command);

        return session;
    }

    /// Request subsystem (e.g., "sftp") on a session channel
    ///
    /// Opens a session channel, requests the subsystem, and returns the channel.
    pub fn requestSubsystem(self: *Self, subsystem_name: []const u8) !channels.SessionChannel {
        var session = try self.openSession();
        errdefer session.close() catch {};

        try session.waitForConfirmation();
        try session.requestSubsystem(subsystem_name);

        return session;
    }

    /// Open SFTP session (convenience method)
    ///
    /// Opens a session channel, requests "sftp" subsystem, and returns
    /// an SFTP channel ready for file operations.
    pub fn openSftp(self: *Self) !sftp.SftpChannel {
        const session = try self.requestSubsystem("sftp");
        return sftp.SftpChannel.init(self.allocator, session);
    }
};

/// Active SSH/QUIC server connection handler
pub const ServerConnection = struct {
    allocator: Allocator,
    transport: quic_transport.QuicTransport,
    kex: kex_exchange.ServerKeyExchange,
    channel_manager: channels.ChannelManager,

    const Self = @This();

    /// Accept and handle an incoming SSH/QUIC connection
    ///
    /// This performs:
    /// 1. Process SSH_QUIC_INIT
    /// 2. Perform key exchange and derive secrets
    /// 3. Initialize QUIC connection with derived secrets
    ///
    /// Note: This is used for testing. For production, use ConnectionListener.acceptConnection()
    /// which also handles UDP I/O.
    pub fn accept(
        allocator: Allocator,
        config: ServerConfig,
        init_data: []const u8,
    ) !Self {
        std.log.info("Processing SSH_QUIC_INIT ({} bytes)...", .{init_data.len});

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

        // Note: reply_data is created but not sent (caller would need to send it)
        std.log.info("Created SSH_QUIC_REPLY ({} bytes)", .{result.reply_data.len});

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

        // Initialize channel manager
        const channel_manager = channels.ChannelManager.init(allocator, &transport, true);

        return Self{
            .allocator = allocator,
            .transport = transport,
            .kex = kex,
            .channel_manager = channel_manager,
        };
    }

    pub fn deinit(self: *Self) void {
        self.channel_manager.deinit();
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

    /// Handle client authentication request
    ///
    /// Receives authentication request on stream 0, validates credentials,
    /// and sends response. Returns true if authentication succeeds.
    ///
    /// Use setPasswordValidator() and setPublicKeyValidator() to provide
    /// credential validation callbacks.
    pub fn handleAuthentication(
        self: *Self,
        password_validator: ?auth.AuthServer.PasswordValidator,
        publickey_validator: ?auth.AuthServer.PublicKeyValidator,
    ) !bool {
        var auth_server = auth.AuthServer.init(self.allocator);
        if (password_validator) |validator| {
            auth_server.setPasswordValidator(validator);
        }
        if (publickey_validator) |validator| {
            auth_server.setPublicKeyValidator(validator);
        }

        // Receive authentication request on stream 0
        var request_buffer: [4096]u8 = undefined;
        const request_len = try self.transport.receiveFromStream(0, &request_buffer);
        const request_data = request_buffer[0..request_len];

        // Get exchange hash from key exchange
        const exchange_hash = self.kex.getExchangeHash();

        // Process authentication request
        var response = try auth_server.processRequest(request_data, exchange_hash);
        defer response.deinit(self.allocator);

        // Send response to client
        try self.transport.sendOnStream(0, response.data);

        return response.success;
    }

    /// Send authentication banner to client
    pub fn sendAuthBanner(self: *Self, message: []const u8, language_tag: []const u8) !void {
        var auth_server = auth.AuthServer.init(self.allocator);
        const banner_data = try auth_server.sendBanner(message, language_tag);
        defer self.allocator.free(banner_data);

        try self.transport.sendOnStream(0, banner_data);
    }

    /// Create a session server for handling client session requests
    pub fn createSessionServer(self: *Self) channels.SessionServer {
        return channels.SessionServer.init(self.allocator, &self.channel_manager);
    }

    /// Accept incoming session channel (convenience method)
    pub fn acceptSession(self: *Self, stream_id: u64) !void {
        try self.channel_manager.acceptChannel(stream_id);
    }

    /// Send data on a session channel
    pub fn sendSessionData(self: *Self, stream_id: u64, data: []const u8) !void {
        try self.channel_manager.sendData(stream_id, data);
    }

    /// Receive data from a session channel
    pub fn receiveSessionData(self: *Self, stream_id: u64) ![]u8 {
        return self.channel_manager.receiveData(stream_id);
    }

    /// Send EOF on a session channel
    pub fn sendSessionEof(self: *Self, stream_id: u64) !void {
        try self.channel_manager.sendEof(stream_id);
    }

    /// Close a session channel
    pub fn closeSession(self: *Self, stream_id: u64) !void {
        try self.channel_manager.closeChannel(stream_id);
    }
};

/// Connection listener for accepting multiple client connections
pub const ConnectionListener = struct {
    allocator: Allocator,
    config: ServerConfig,
    udp_transport: udp.KeyExchangeTransport,

    const Self = @This();

    /// Start listening for SSH/QUIC connections
    pub fn listen(allocator: Allocator, config: ServerConfig) !Self {
        std.log.info("SSH/QUIC server listening on {}:{}", .{
            config.listen_address,
            config.listen_port,
        });

        // Initialize UDP transport for receiving key exchange messages
        var udp_transport = try udp.KeyExchangeTransport.initServer(
            allocator,
            config.listen_address,
            config.listen_port,
        );
        errdefer udp_transport.deinit();

        return Self{
            .allocator = allocator,
            .config = config,
            .udp_transport = udp_transport,
        };
    }

    pub fn deinit(self: *Self) void {
        self.udp_transport.deinit();
    }

    /// Accept the next incoming connection
    ///
    /// This blocks until a client connects
    pub fn acceptConnection(self: *Self) !ServerConnection {
        std.log.info("Waiting for client connection...", .{});

        // Receive SSH_QUIC_INIT from client
        const init_result = try self.udp_transport.receiveInit();
        defer self.allocator.free(init_result.init_data);

        std.log.info("Received init from client, processing...", .{});

        // Initialize server key exchange
        var kex = kex_exchange.ServerKeyExchange.init(self.allocator, self.config.random);
        errdefer kex.deinit();

        // Process init and create reply
        const result = try kex.processInitAndCreateReply(
            init_result.init_data,
            self.config.quic_versions,
            self.config.quic_params,
            self.config.host_key,
            self.config.host_private_key,
        );
        defer self.allocator.free(result.reply_data);

        // Send SSH_QUIC_REPLY back to client
        try self.udp_transport.sendReply(result.reply_data, init_result.client_address);

        // Initialize QUIC transport with derived secrets
        std.log.info("Initializing QUIC connection...", .{});
        var transport = try quic_transport.QuicTransport.init(
            self.allocator,
            self.config.listen_address,
            self.config.listen_port,
            &result.client_secret,
            &result.server_secret,
            true, // server mode
        );
        errdefer transport.deinit();

        // Initialize channel manager
        const channel_manager = channels.ChannelManager.init(self.allocator, &transport, true);

        std.log.info("Client connection established", .{});

        return ServerConnection{
            .allocator = self.allocator,
            .transport = transport,
            .kex = kex,
            .channel_manager = channel_manager,
        };
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
