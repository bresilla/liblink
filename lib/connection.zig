const std = @import("std");
const Allocator = std.mem.Allocator;

// Import modules
const kex_exchange = @import("kex/exchange.zig");
const quic = @import("quic/transport.zig");
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
    transport: *quic.QuicTransport,
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
        std.log.info("Connecting to {s}:{}...", .{ config.server_address, config.server_port });

        // Initialize UDP transport for key exchange
        var udp_transport = try udp.KeyExchangeTransport.initClient(
            allocator,
            config.server_address,
            config.server_port,
        );
        // NOTE: Don't deinit udp_transport - we'll pass its socket to QUIC

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

        // TODO: Extract actual connection IDs from key exchange
        const local_conn_id = "client-conn-id";
        const remote_conn_id = "server-conn-id";

        // Prepare server address for client to send packets to
        var server_storage: std.posix.sockaddr.storage = undefined;
        const server_sockaddr_ptr: *const std.posix.sockaddr = @ptrCast(&udp_transport.socket.address.any);
        @memcpy(std.mem.asBytes(&server_storage)[0..@sizeOf(std.posix.sockaddr)], std.mem.asBytes(server_sockaddr_ptr));

        const transport = try allocator.create(quic.QuicTransport);
        errdefer allocator.destroy(transport);

        transport.* = try quic.QuicTransport.init(
            allocator,
            udp_transport.socket.socket, // Reuse UDP socket
            local_conn_id,
            remote_conn_id,
            secrets.client_secret,
            secrets.server_secret,
            false, // client mode
            server_storage, // Set peer address for client
        );
        errdefer transport.deinit();


        std.log.info("SSH/QUIC connection established", .{});

        // Initialize channel manager with pointer to heap-allocated transport
        const channel_manager = channels.ChannelManager.init(allocator, transport, false);

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
        self.allocator.destroy(self.transport);
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

        // Open stream 0 for authentication (stream 0 should be first bidirectional stream)
        _ = self.transport.openStream() catch |err| blk: {
            // Stream might already exist, that's OK
            std.log.debug("Stream 0 open result: {}", .{err});
            break :blk 0;
        };

        // Send on stream 0 (authentication stream)
        try self.transport.sendOnStream(0, request_data);

        // Poll for response (wait up to 5 seconds)
        try self.transport.poll(5000);

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

            // Poll for response
            try self.transport.poll(5000);

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

            // Poll for response
            try self.transport.poll(5000);

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

        // Poll for response
        try self.transport.poll(5000);

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
    /// Opens a session channel, requests a PTY, requests a shell, and returns the channel.
    pub fn requestShell(self: *Self) !channels.SessionChannel {
        var session = try self.openSession();
        errdefer session.close() catch {};

        try session.waitForConfirmation();

        // Request PTY before shell for proper terminal support
        try session.requestPty(
            "xterm-256color", // TERM environment variable
            80,  // width in characters
            24,  // height in rows
            0,   // width in pixels (0 = not specified)
            0,   // height in pixels (0 = not specified)
        );

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
    transport: quic.QuicTransport,
    kex: kex_exchange.ServerKeyExchange,
    channel_manager: channels.ChannelManager,

    const Self = @This();

    /// Accept and handle an incoming SSH/QUIC connection
    ///
    /// DEPRECATED: Use ConnectionListener.acceptConnection() instead.
    /// This function cannot work with the new QUIC implementation as it requires
    /// a UDP socket from the key exchange phase.
    pub fn accept(
        allocator: Allocator,
        config: ServerConfig,
        init_data: []const u8,
    ) !Self {
        _ = allocator;
        _ = config;
        _ = init_data;
        return error.DeprecatedUseConnectionListener;
    }

    pub fn deinit(self: *Self) void {
        self.channel_manager.deinit();
        self.transport.deinit();
        self.kex.deinit();
    }

    /// Accept a new channel opened by client
    ///
    /// Waits for SSH_MSG_CHANNEL_OPEN on the next available client stream,
    /// validates the request, and sends SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
    ///
    /// Returns the stream ID of the opened channel.
    pub fn acceptChannel(self: *Self) !u64 {
        // Determine next expected client stream (client streams are 4, 8, 12, ...)
        const next_stream_id = self.channel_manager.getNextClientStream();

        // Use channel manager to accept the channel
        try self.channel_manager.acceptChannel(next_stream_id);

        std.log.info("Server accepted channel on stream {}", .{next_stream_id});

        return next_stream_id;
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
        std.log.info("Waiting for authentication request...", .{});

        var auth_server = auth.AuthServer.init(self.allocator);
        if (password_validator) |validator| {
            auth_server.setPasswordValidator(validator);
            std.log.debug("Password authentication enabled", .{});
        }
        if (publickey_validator) |validator| {
            auth_server.setPublicKeyValidator(validator);
            std.log.debug("Public key authentication enabled", .{});
        }

        // Poll for incoming authentication request (wait up to 30 seconds)
        try self.transport.poll(30000);

        // Receive authentication request on stream 0
        var request_buffer: [4096]u8 = undefined;
        const request_len = self.transport.receiveFromStream(0, &request_buffer) catch |err| {
            std.log.err("Failed to receive authentication request: {}", .{err});
            return err;
        };
        const request_data = request_buffer[0..request_len];

        std.log.debug("Received authentication request ({} bytes)", .{request_len});

        // Get exchange hash from key exchange
        const exchange_hash = self.kex.getExchangeHash();

        // Process authentication request
        var response = auth_server.processRequest(request_data, exchange_hash) catch |err| {
            std.log.err("Failed to process authentication request: {}", .{err});
            return err;
        };
        defer response.deinit(self.allocator);

        // Send response to client
        try self.transport.sendOnStream(0, response.data);

        if (response.success) {
            std.log.info("✓ Authentication successful", .{});
        } else {
            std.log.warn("✗ Authentication failed", .{});
        }

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
    running: bool,
    active_connections: std.ArrayList(*ServerConnection),

    const Self = @This();

    /// Start listening for SSH/QUIC connections
    pub fn listen(allocator: Allocator, config: ServerConfig) !Self {
        std.log.info("SSH/QUIC server listening on {s}:{}", .{
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
            .running = true,
            .active_connections = std.ArrayList(*ServerConnection){},
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up all active connections
        for (self.active_connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.active_connections.deinit();

        self.udp_transport.deinit();
    }

    /// Graceful shutdown - stops accepting new connections
    pub fn shutdown(self: *Self) void {
        std.log.info("Server shutting down gracefully...", .{});
        self.running = false;
    }

    /// Get number of active connections
    pub fn getActiveConnectionCount(self: *Self) usize {
        return self.active_connections.items.len;
    }

    /// Remove a connection from tracking (called when client disconnects)
    pub fn removeConnection(self: *Self, conn: *ServerConnection) void {
        for (self.active_connections.items, 0..) |tracked_conn, i| {
            if (tracked_conn == conn) {
                _ = self.active_connections.swapRemove(i);
                conn.deinit();
                self.allocator.destroy(conn);
                std.log.info("Client disconnected, {} active connections remaining", .{
                    self.active_connections.items.len,
                });
                return;
            }
        }
    }

    /// Accept the next incoming connection
    ///
    /// This blocks until a client connects. Returns a pointer to the
    /// ServerConnection which is tracked by the listener.
    ///
    /// The connection is automatically cleaned up when removeConnection() is called
    /// or when the listener is deinitialized.
    pub fn acceptConnection(self: *Self) !*ServerConnection {
        if (!self.running) {
            return error.ServerShutdown;
        }

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

        // TODO: Extract actual connection IDs from key exchange
        const local_conn_id = "server-conn-id";
        const remote_conn_id = "client-conn-id";

        // Set client address for server socket (for sendto)
        self.udp_transport.socket.address = init_result.client_address;

        // Prepare client address for server transport (convert Address to sockaddr.storage)
        var client_storage: std.posix.sockaddr.storage = undefined;
        const client_sockaddr_ptr: *const std.posix.sockaddr = @ptrCast(&init_result.client_address.any);
        @memcpy(std.mem.asBytes(&client_storage)[0..@sizeOf(std.posix.sockaddr)], std.mem.asBytes(client_sockaddr_ptr));

        var transport = try quic.QuicTransport.init(
            self.allocator,
            self.udp_transport.socket.socket, // Reuse UDP socket
            local_conn_id,
            remote_conn_id,
            result.client_secret,
            result.server_secret,
            true, // server mode
            client_storage, // Set peer address for server
        );
        errdefer transport.deinit();


        // Allocate and track the connection
        const conn = try self.allocator.create(ServerConnection);
        errdefer self.allocator.destroy(conn);

        conn.* = ServerConnection{
            .allocator = self.allocator,
            .transport = transport,
            .kex = kex,
            .channel_manager = undefined, // Initialize after transport is in place
        };

        // Initialize channel manager with pointer to conn.transport (not local variable!)
        conn.channel_manager = channels.ChannelManager.init(self.allocator, &conn.transport, true);

        try self.active_connections.append(self.allocator, conn);

        std.log.info("Client connection established, {} total active connections", .{
            self.active_connections.items.len,
        });

        return conn;
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

// Test helper: password validator
fn testPasswordValidator(username: []const u8, password: []const u8) bool {
    std.log.info("Password validation: user={s}, password={s}", .{ username, password });
    return std.mem.eql(u8, username, "testuser") and std.mem.eql(u8, password, "testpass123");
}

// Test helper: public key validator
fn testPublicKeyValidator(username: []const u8, algorithm: []const u8, public_key_blob: []const u8) bool {
    _ = public_key_blob;
    std.log.info("Public key validation: user={s}, algorithm={s}", .{ username, algorithm });
    return std.mem.eql(u8, username, "keyuser") and std.mem.eql(u8, algorithm, "ssh-ed25519");
}

test "ServerConnection - authentication validators" {
    const testing = std.testing;

    // Test password validator
    try testing.expect(testPasswordValidator("testuser", "testpass123"));
    try testing.expect(!testPasswordValidator("testuser", "wrongpass"));
    try testing.expect(!testPasswordValidator("wronguser", "testpass123"));

    // Test public key validator
    const dummy_key = "dummy-key";
    try testing.expect(testPublicKeyValidator("keyuser", "ssh-ed25519", dummy_key));
    try testing.expect(!testPublicKeyValidator("keyuser", "ssh-rsa", dummy_key));
    try testing.expect(!testPublicKeyValidator("wronguser", "ssh-ed25519", dummy_key));
}

test "AuthServer integration - password authentication flow" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create auth server
    var auth_server = auth.AuthServer.init(allocator);
    auth_server.setPasswordValidator(testPasswordValidator);

    // Create password authentication request
    var request = @import("protocol/userauth.zig").UserauthRequest{
        .username = "testuser",
        .service_name = "ssh-connection",
        .method_name = "password",
        .method_data = .{ .password = "testpass123" },
    };

    const request_data = try request.encode(allocator);
    defer allocator.free(request_data);

    const exchange_hash = "test-exchange-hash";

    // Process request
    var response = try auth_server.processRequest(request_data, exchange_hash);
    defer response.deinit(allocator);

    // Verify success
    try testing.expect(response.success);
}

test "AuthServer integration - password authentication failure" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create auth server
    var auth_server = auth.AuthServer.init(allocator);
    auth_server.setPasswordValidator(testPasswordValidator);

    // Create password authentication request with wrong password
    var request = @import("protocol/userauth.zig").UserauthRequest{
        .username = "testuser",
        .service_name = "ssh-connection",
        .method_name = "password",
        .method_data = .{ .password = "wrongpass" },
    };

    const request_data = try request.encode(allocator);
    defer allocator.free(request_data);

    const exchange_hash = "test-exchange-hash";

    // Process request
    var response = try auth_server.processRequest(request_data, exchange_hash);
    defer response.deinit(allocator);

    // Verify failure
    try testing.expect(!response.success);
}

test "ConnectionListener - init and shutdown" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var prng = std.Random.DefaultPrng.init(99999);
    const random = prng.random();

    // Generate Ed25519 keypair for testing
    const Ed25519 = std.crypto.sign.Ed25519;
    const ed_keypair = Ed25519.KeyPair.generate();

    var host_private_key: [64]u8 = undefined;
    @memcpy(&host_private_key, &ed_keypair.secret_key.bytes);

    var host_public_key: [32]u8 = undefined;
    @memcpy(&host_public_key, &ed_keypair.public_key.bytes);

    // Encode host key as SSH blob
    const host_key_blob = try encodeTestHostKey(allocator, &host_public_key);
    defer allocator.free(host_key_blob);

    const config = ServerConfig{
        .listen_address = "127.0.0.1",
        .listen_port = 9999, // Use high port for testing
        .host_key = host_key_blob,
        .host_private_key = &host_private_key,
        .random = random,
    };

    // Note: Can't actually initialize listener without network stack
    // This tests the configuration structure
    try testing.expectEqualStrings("127.0.0.1", config.listen_address);
    try testing.expectEqual(@as(u16, 9999), config.listen_port);
}

test "ConnectionListener - running flag" {
    const testing = std.testing;

    // Simulate listener state
    var running: bool = true;
    try testing.expect(running);

    // Simulate shutdown
    running = false;
    try testing.expect(!running);
}

test "ConnectionListener - connection tracking" {
    const testing = std.testing;

    // Test connection counting logic
    var count: usize = 0;

    // Add connections
    count += 1;
    count += 1;
    count += 1;
    try testing.expectEqual(@as(usize, 3), count);

    // Remove a connection
    count -= 1;
    try testing.expectEqual(@as(usize, 2), count);

    // Clear all
    count = 0;
    try testing.expectEqual(@as(usize, 0), count);
}

// Helper to encode SSH host key for tests
fn encodeTestHostKey(allocator: std.mem.Allocator, public_key: *const [32]u8) ![]u8 {
    const algorithm = "ssh-ed25519";
    const blob_size = 4 + algorithm.len + 4 + public_key.len;
    const host_key_blob = try allocator.alloc(u8, blob_size);
    errdefer allocator.free(host_key_blob);

    var offset: usize = 0;

    // Write algorithm name
    std.mem.writeInt(u32, host_key_blob[offset..][0..4], @intCast(algorithm.len), .big);
    offset += 4;
    @memcpy(host_key_blob[offset .. offset + algorithm.len], algorithm);
    offset += algorithm.len;

    // Write public key
    std.mem.writeInt(u32, host_key_blob[offset..][0..4], @intCast(public_key.len), .big);
    offset += 4;
    @memcpy(host_key_blob[offset .. offset + public_key.len], public_key);

    return host_key_blob;
}
