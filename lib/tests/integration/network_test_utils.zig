const std = @import("std");
const syslink = @import("../../syslink.zig");

pub const USERNAME = "e2e-user";
pub const PASSWORD = "e2e-pass";

pub const RunningServer = struct {
    allocator: std.mem.Allocator,
    listener: syslink.connection.ConnectionListener,
    host_key_blob: []u8,

    pub fn deinit(self: *RunningServer) void {
        self.listener.deinit();
        self.allocator.free(self.host_key_blob);
    }
};

pub fn validatePassword(username: []const u8, password: []const u8) bool {
    return std.mem.eql(u8, username, USERNAME) and std.mem.eql(u8, password, PASSWORD);
}

pub fn encodeHostKeyBlob(allocator: std.mem.Allocator, public_key: *const [32]u8) ![]u8 {
    const alg = "ssh-ed25519";
    const size = 4 + alg.len + 4 + 32;
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var writer = syslink.protocol.wire.Writer{ .buffer = buffer };
    try writer.writeString(alg);
    try writer.writeString(public_key);
    return buffer;
}

pub fn chooseTestPort(base: u16) u16 {
    const ts: u64 = @intCast(std.time.nanoTimestamp());
    return base + @as(u16, @intCast(ts % 2000));
}

pub fn startLocalTestServer(
    allocator: std.mem.Allocator,
    port: u16,
    random: std.Random,
) !RunningServer {
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.generate();
    var host_private_key: [64]u8 = undefined;
    @memcpy(&host_private_key, &ed_keypair.secret_key.bytes);

    const host_key_blob = try encodeHostKeyBlob(allocator, &ed_keypair.public_key.bytes);
    errdefer allocator.free(host_key_blob);

    var listener = try syslink.connection.startServer(
        allocator,
        "127.0.0.1",
        port,
        host_key_blob,
        &host_private_key,
        random,
    );
    errdefer listener.deinit();

    return .{
        .allocator = allocator,
        .listener = listener,
        .host_key_blob = host_key_blob,
    };
}

pub fn acceptAuthenticatedConnection(listener: *syslink.connection.ConnectionListener) !*syslink.connection.ServerConnection {
    const server_conn = try listener.acceptConnection();
    const auth_ok = try server_conn.handleAuthentication(validatePassword, null);
    if (!auth_ok) {
        listener.removeConnection(server_conn);
        return error.AuthenticationFailed;
    }
    return server_conn;
}

pub fn connectAuthenticatedClient(
    allocator: std.mem.Allocator,
    port: u16,
    prng_seed: u64,
) !syslink.connection.ClientConnection {
    var prng = std.Random.DefaultPrng.init(prng_seed);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", port, random);
    errdefer client.deinit();

    const authed = try client.authenticatePassword(USERNAME, PASSWORD);
    if (!authed) {
        return error.AuthenticationFailed;
    }

    return client;
}

pub fn requireEnvEnabled(allocator: std.mem.Allocator, env_var: []const u8) !void {
    const enabled = std.process.getEnvVarOwned(allocator, env_var) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(enabled);

    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;
}

pub fn waitForReadyFlag(ready: *std.atomic.Value(bool), max_attempts: usize, sleep_ms: u64) bool {
    var wait_count: usize = 0;
    while (!ready.load(.acquire) and wait_count < max_attempts) : (wait_count += 1) {
        std.Thread.sleep(sleep_ms * std.time.ns_per_ms);
    }
    return ready.load(.acquire);
}

pub fn waitForSessionChannel(server_conn: *syslink.connection.ServerConnection, timeout_ms: u32) !u64 {
    const deadline_ms = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline_ms) {
        server_conn.transport.poll(50) catch {};

        const stream_id = server_conn.acceptChannel() catch {
            std.Thread.sleep(2 * std.time.ns_per_ms);
            continue;
        };
        return stream_id;
    }

    return error.ChannelAcceptTimeout;
}
