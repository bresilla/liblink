const std = @import("std");
const Allocator = std.mem.Allocator;

// Import protocol components
const kex_init = @import("../protocol/kex_init.zig");
const kex_reply = @import("../protocol/kex_reply.zig");
const kex_curve25519 = @import("../protocol/kex_curve25519.zig");
const shared_secrets = @import("shared_secrets.zig");
const crypto = @import("../crypto/crypto.zig");
const constants = @import("../common/constants.zig");

/// Client key exchange state machine
pub const ClientKeyExchange = struct {
    allocator: Allocator,
    random: std.Random,
    ephemeral_key: kex_curve25519.ClientEphemeralKey,
    init_message: ?kex_init.SshQuicInit,
    reply_message: ?kex_reply.SshQuicReply,
    shared_secret: ?[32]u8,
    exchange_hash: ?[]u8,

    const Self = @This();

    /// Initialize client key exchange
    pub fn init(allocator: Allocator, random: std.Random) Self {
        const ephemeral_key = kex_curve25519.ClientEphemeralKey.generate(random);

        return Self{
            .allocator = allocator,
            .random = random,
            .ephemeral_key = ephemeral_key,
            .init_message = null,
            .reply_message = null,
            .shared_secret = null,
            .exchange_hash = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.init_message) |*msg| {
            msg.deinit(self.allocator);
        }
        if (self.reply_message) |*msg| {
            msg.deinit(self.allocator);
        }
        if (self.exchange_hash) |hash| {
            self.allocator.free(hash);
        }
    }

    /// Create SSH_QUIC_INIT message
    ///
    /// Parameters:
    /// - server_name: Optional server name indication (SNI)
    /// - quic_versions: List of supported QUIC versions
    /// - quic_params: QUIC transport parameters
    pub fn createInit(
        self: *Self,
        server_name: []const u8,
        quic_versions: []const u32,
        quic_params: []const u8,
    ) ![]u8 {
        // Encode client ephemeral key data
        const client_kex_data = try self.ephemeral_key.encodeClientData(self.allocator);
        defer self.allocator.free(client_kex_data);

        // Create SSH_QUIC_INIT message
        const init_msg = kex_init.SshQuicInit{
            .client_connection_id = "",
            .server_name_indication = server_name,
            .client_quic_versions = quic_versions,
            .client_quic_trnsp_params = quic_params,
            .client_sig_algs = constants.DEFAULT_SIG_ALGS,
            .trusted_fingerprints = &[_][]const u8{},
            .client_kex_algs = &[_]kex_init.KexAlgorithm{
                .{
                    .name = constants.KEX_CURVE25519_SHA256,
                    .data = client_kex_data,
                },
            },
            .quic_tls_cipher_suites = &[_][]const u8{constants.DEFAULT_CIPHER_SUITE},
            .ext_pairs = &[_]kex_init.ExtensionPair{},
        };

        // Encode the message
        const encoded = try init_msg.encode(self.allocator);

        // Save for exchange hash calculation
        self.init_message = try duplicateInit(&init_msg, self.allocator);

        return encoded;
    }

    /// Process SSH_QUIC_REPLY message
    ///
    /// Returns: (client_secret, server_secret) for QUIC initialization
    pub fn processReply(
        self: *Self,
        reply_data: []const u8,
    ) !struct { client_secret: [32]u8, server_secret: [32]u8 } {
        // Decode SSH_QUIC_REPLY
        var reply = try kex_reply.SshQuicReply.decode(self.allocator, reply_data);
        errdefer reply.deinit(self.allocator);

        // Check for error reply
        if (reply.isErrorReply()) {
            const reason = reply.getDiscReason() orelse 0;
            const desc = reply.getErrorDesc() orelse "Unknown error";
            std.log.err("Server rejected key exchange: code={}, desc={s}", .{ reason, desc });
            return error.ServerRejectedKeyExchange;
        }

        // Decode server ephemeral key data
        const server_data = try kex_curve25519.ServerEphemeralKey.decodeServerData(
            self.allocator,
            reply.server_kex_alg_data,
        );
        defer {
            self.allocator.free(server_data.host_key);
            self.allocator.free(server_data.signature);
        }

        // Calculate shared secret K
        const shared_secret = try kex_curve25519.calculateSharedSecret(
            &self.ephemeral_key.private_key,
            &server_data.public_key,
        );

        // Encode init content for hash calculation
        const init_encoded = try self.init_message.?.encode(self.allocator);
        defer self.allocator.free(init_encoded);

        // Encode reply content without kex data for hash calculation
        const reply_without_kex = try encodeReplyWithoutKex(&reply, self.allocator);
        defer self.allocator.free(reply_without_kex);

        // Calculate exchange hash H
        const exchange_hash = try kex_curve25519.calculateExchangeHash(
            self.allocator,
            init_encoded,
            reply_without_kex,
            server_data.host_key,
            &server_data.public_key,
            &shared_secret,
        );

        // TODO: Verify server signature over exchange hash

        // Derive QUIC secrets
        const quic_secrets = try shared_secrets.deriveQuicSecrets(
            &shared_secret,
            exchange_hash,
            self.allocator,
        );

        // Save state
        self.shared_secret = shared_secret;
        self.exchange_hash = exchange_hash;
        self.reply_message = reply;

        return .{
            .client_secret = quic_secrets.client_secret,
            .server_secret = quic_secrets.server_secret,
        };
    }
};

/// Server key exchange state machine
pub const ServerKeyExchange = struct {
    allocator: Allocator,
    random: std.Random,
    ephemeral_key: ?kex_curve25519.ServerEphemeralKey,
    init_message: ?kex_init.SshQuicInit,
    shared_secret: ?[32]u8,
    exchange_hash: ?[]u8,

    const Self = @This();

    pub fn init(allocator: Allocator, random: std.Random) Self {
        return Self{
            .allocator = allocator,
            .random = random,
            .ephemeral_key = null,
            .init_message = null,
            .shared_secret = null,
            .exchange_hash = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.init_message) |*msg| {
            msg.deinit(self.allocator);
        }
        if (self.exchange_hash) |hash| {
            self.allocator.free(hash);
        }
    }

    /// Process SSH_QUIC_INIT and create SSH_QUIC_REPLY
    ///
    /// Parameters:
    /// - init_data: Encoded SSH_QUIC_INIT message
    /// - quic_versions: Supported QUIC versions
    /// - quic_params: Server QUIC transport parameters
    /// - host_key: Server host key (Ed25519 public key)
    /// - host_private_key: Server host private key (for signing)
    ///
    /// Returns: (reply_data, client_secret, server_secret)
    pub fn processInitAndCreateReply(
        self: *Self,
        init_data: []const u8,
        quic_versions: []const u32,
        quic_params: []const u8,
        host_key: []const u8,
        host_private_key: *const [64]u8,
    ) !struct { reply_data: []u8, client_secret: [32]u8, server_secret: [32]u8 } {
        // Decode SSH_QUIC_INIT
        var init_msg = try kex_init.SshQuicInit.decode(self.allocator, init_data);
        errdefer init_msg.deinit(self.allocator);

        // Validate init message
        if (init_msg.client_kex_algs.len == 0) {
            return error.NoKeyExchangeAlgorithms;
        }

        // Find curve25519-sha256 in client's kex algorithms
        var client_kex_data: ?[]const u8 = null;
        for (init_msg.client_kex_algs) |kex| {
            if (std.mem.eql(u8, kex.name, constants.KEX_CURVE25519_SHA256)) {
                client_kex_data = kex.data;
                break;
            }
        }

        if (client_kex_data == null) {
            return error.UnsupportedKeyExchangeAlgorithm;
        }

        // Decode client ephemeral key
        const client_ephemeral = try kex_curve25519.ClientEphemeralKey.decodeClientData(
            self.allocator,
            client_kex_data.?,
        );

        // Generate server ephemeral key
        const server_ephemeral = kex_curve25519.ServerEphemeralKey.generate(self.random);

        // Calculate shared secret K
        const shared_secret = try kex_curve25519.calculateSharedSecret(
            &server_ephemeral.private_key,
            &client_ephemeral.public_key,
        );

        // Encode reply content without kex data for hash calculation
        const reply_without_kex = try encodeReplyWithoutKexFromParams(
            self.allocator,
            &init_msg,
            quic_versions,
            quic_params,
        );
        defer self.allocator.free(reply_without_kex);

        // Calculate exchange hash H
        const exchange_hash = try kex_curve25519.calculateExchangeHash(
            self.allocator,
            init_data,
            reply_without_kex,
            host_key,
            &server_ephemeral.public_key,
            &shared_secret,
        );
        errdefer self.allocator.free(exchange_hash);

        // Sign exchange hash with server host key
        const signature = try signExchangeHash(exchange_hash, host_private_key, self.allocator);
        defer self.allocator.free(signature);

        // Encode server kex data
        const server_kex_data = try server_ephemeral.encodeServerData(
            self.allocator,
            host_key,
            signature,
        );
        defer self.allocator.free(server_kex_data);

        // Create SSH_QUIC_REPLY
        const reply = kex_reply.SshQuicReply{
            .client_connection_id = init_msg.client_connection_id,
            .server_connection_id = "server-conn-id", // TODO: Generate properly
            .server_quic_versions = quic_versions,
            .server_quic_trnsp_params = quic_params,
            .server_sig_algs = constants.DEFAULT_SIG_ALGS,
            .server_kex_algs = constants.KEX_CURVE25519_SHA256,
            .quic_tls_cipher_suites = &[_][]const u8{constants.DEFAULT_CIPHER_SUITE},
            .ext_pairs = &[_]kex_reply.ExtensionPair{},
            .server_kex_alg_data = server_kex_data,
        };

        // Encode reply
        const reply_data = try reply.encode(self.allocator);

        // Derive QUIC secrets
        const quic_secrets = try shared_secrets.deriveQuicSecrets(
            &shared_secret,
            exchange_hash,
            self.allocator,
        );

        // Save state
        self.ephemeral_key = server_ephemeral;
        self.init_message = init_msg;
        self.shared_secret = shared_secret;
        self.exchange_hash = exchange_hash;

        return .{
            .reply_data = reply_data,
            .client_secret = quic_secrets.client_secret,
            .server_secret = quic_secrets.server_secret,
        };
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Duplicate SSH_QUIC_INIT for storage
fn duplicateInit(init: *const kex_init.SshQuicInit, allocator: Allocator) !kex_init.SshQuicInit {
    const client_conn_id = try allocator.dupe(u8, init.client_connection_id);
    errdefer allocator.free(client_conn_id);

    const server_name = try allocator.dupe(u8, init.server_name_indication);
    errdefer allocator.free(server_name);

    const quic_versions = try allocator.dupe(u32, init.client_quic_versions);
    errdefer allocator.free(quic_versions);

    const quic_params = try allocator.dupe(u8, init.client_quic_trnsp_params);
    errdefer allocator.free(quic_params);

    const sig_algs = try allocator.dupe(u8, init.client_sig_algs);
    errdefer allocator.free(sig_algs);

    // Copy trusted fingerprints
    const fingerprints = try allocator.alloc([]const u8, init.trusted_fingerprints.len);
    errdefer allocator.free(fingerprints);

    for (init.trusted_fingerprints, 0..) |fp, i| {
        fingerprints[i] = try allocator.dupe(u8, fp);
    }

    // Copy kex algorithms
    const kex_algs = try allocator.alloc(kex_init.KexAlgorithm, init.client_kex_algs.len);
    errdefer allocator.free(kex_algs);

    for (init.client_kex_algs, 0..) |kex, i| {
        kex_algs[i] = .{
            .name = try allocator.dupe(u8, kex.name),
            .data = try allocator.dupe(u8, kex.data),
        };
    }

    // Copy cipher suites
    const cipher_suites = try allocator.alloc([]const u8, init.quic_tls_cipher_suites.len);
    errdefer allocator.free(cipher_suites);

    for (init.quic_tls_cipher_suites, 0..) |suite, i| {
        cipher_suites[i] = try allocator.dupe(u8, suite);
    }

    // Copy extension pairs
    const ext_pairs = try allocator.alloc(kex_init.ExtensionPair, init.ext_pairs.len);
    errdefer allocator.free(ext_pairs);

    for (init.ext_pairs, 0..) |ext, i| {
        ext_pairs[i] = .{
            .name = try allocator.dupe(u8, ext.name),
            .data = try allocator.dupe(u8, ext.data),
        };
    }

    return kex_init.SshQuicInit{
        .client_connection_id = client_conn_id,
        .server_name_indication = server_name,
        .client_quic_versions = quic_versions,
        .client_quic_trnsp_params = quic_params,
        .client_sig_algs = sig_algs,
        .trusted_fingerprints = fingerprints,
        .client_kex_algs = kex_algs,
        .quic_tls_cipher_suites = cipher_suites,
        .ext_pairs = ext_pairs,
    };
}

/// Encode SSH_QUIC_REPLY without server_kex_alg_data (for exchange hash)
fn encodeReplyWithoutKex(reply: *const kex_reply.SshQuicReply, allocator: Allocator) ![]u8 {
    const modified = kex_reply.SshQuicReply{
        .client_connection_id = reply.client_connection_id,
        .server_connection_id = reply.server_connection_id,
        .server_quic_versions = reply.server_quic_versions,
        .server_quic_trnsp_params = reply.server_quic_trnsp_params,
        .server_sig_algs = reply.server_sig_algs,
        .server_kex_algs = reply.server_kex_algs,
        .quic_tls_cipher_suites = reply.quic_tls_cipher_suites,
        .ext_pairs = reply.ext_pairs,
        .server_kex_alg_data = "", // Empty for exchange hash
    };

    return modified.encode(allocator);
}

/// Encode SSH_QUIC_REPLY from parameters (server side, before creating full reply)
fn encodeReplyWithoutKexFromParams(
    allocator: Allocator,
    init: *const kex_init.SshQuicInit,
    quic_versions: []const u32,
    quic_params: []const u8,
) ![]u8 {
    const reply = kex_reply.SshQuicReply{
        .client_connection_id = init.client_connection_id,
        .server_connection_id = "server-conn-id",
        .server_quic_versions = quic_versions,
        .server_quic_trnsp_params = quic_params,
        .server_sig_algs = constants.DEFAULT_SIG_ALGS,
        .server_kex_algs = constants.KEX_CURVE25519_SHA256,
        .quic_tls_cipher_suites = &[_][]const u8{constants.DEFAULT_CIPHER_SUITE},
        .ext_pairs = &[_]kex_reply.ExtensionPair{},
        .server_kex_alg_data = "",
    };

    return reply.encode(allocator);
}

/// Sign exchange hash with Ed25519
fn signExchangeHash(
    exchange_hash: []const u8,
    private_key: *const [64]u8,
    allocator: Allocator,
) ![]u8 {
    _ = exchange_hash;
    _ = private_key;
    // TODO: Implement Ed25519 signature
    // For now, return dummy signature
    const signature = try allocator.alloc(u8, 64);
    @memset(signature, 0xAB);
    return signature;
}

// ============================================================================
// Tests
// ============================================================================

test "ClientKeyExchange - create init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    var client = ClientKeyExchange.init(allocator, random);
    defer client.deinit();

    const quic_versions = [_]u32{1};
    const init_data = try client.createInit("example.com", &quic_versions, "");
    defer allocator.free(init_data);

    // Should be at least minimum size (1200 bytes)
    try testing.expect(init_data.len >= kex_init.min_payload_size);
}

test "Full key exchange - client and server" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    // Client side
    var client = ClientKeyExchange.init(allocator, random);
    defer client.deinit();

    const quic_versions = [_]u32{1};
    const init_data = try client.createInit("localhost", &quic_versions, "client_params");
    defer allocator.free(init_data);

    // Server side
    var server = ServerKeyExchange.init(allocator, random);
    defer server.deinit();

    const host_key = "ssh-ed25519 AAAA...";
    var host_private_key: [64]u8 = undefined;
    random.bytes(&host_private_key);

    const server_result = try server.processInitAndCreateReply(
        init_data,
        &quic_versions,
        "server_params",
        host_key,
        &host_private_key,
    );
    defer allocator.free(server_result.reply_data);

    // Client processes reply
    const client_result = try client.processReply(server_result.reply_data);

    // Secrets should match
    try testing.expectEqualSlices(u8, &client_result.client_secret, &server_result.client_secret);
    try testing.expectEqualSlices(u8, &client_result.server_secret, &server_result.server_secret);

    // Exchange hashes should match
    try testing.expectEqualSlices(u8, client.exchange_hash.?, server.exchange_hash.?);
}
