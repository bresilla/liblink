const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");

const USERNAME = "e2e-user";
const PASSWORD = "e2e-pass";

fn validatePassword(username: []const u8, password: []const u8) bool {
    return std.mem.eql(u8, username, USERNAME) and std.mem.eql(u8, password, PASSWORD);
}

fn encodeHostKeyBlob(allocator: std.mem.Allocator, public_key: *const [32]u8) ![]u8 {
    const alg = "ssh-ed25519";
    const size = 4 + alg.len + 4 + 32;
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var writer = syslink.protocol.wire.Writer{ .buffer = buffer };
    try writer.writeString(alg);
    try writer.writeString(public_key);
    return buffer;
}

const ServerThreadCtx = struct {
    allocator: std.mem.Allocator,
    port: u16,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    auth_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const random = prng.random();

    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.generate();
    var host_private_key: [64]u8 = undefined;
    @memcpy(&host_private_key, &ed_keypair.secret_key.bytes);

    const host_key_blob = encodeHostKeyBlob(ctx.allocator, &ed_keypair.public_key.bytes) catch {
        ctx.failed.store(true, .release);
        return;
    };
    defer ctx.allocator.free(host_key_blob);

    var listener = syslink.connection.startServer(
        ctx.allocator,
        "127.0.0.1",
        ctx.port,
        host_key_blob,
        &host_private_key,
        random,
    ) catch {
        ctx.failed.store(true, .release);
        return;
    };
    defer listener.deinit();

    ctx.ready.store(true, .release);

    const server_conn = listener.acceptConnection() catch {
        ctx.failed.store(true, .release);
        return;
    };
    defer {
        listener.removeConnection(server_conn);
    }

    const ok = server_conn.handleAuthentication(validatePassword, null) catch {
        ctx.failed.store(true, .release);
        return;
    };
    ctx.auth_ok.store(ok, .release);
}

fn chooseTestPort() u16 {
    const ts: u64 = @intCast(std.time.nanoTimestamp());
    const base: u16 = 38000;
    return base + @as(u16, @intCast(ts % 2000));
}

test "Integration: network client/server password auth e2e" {
    const allocator = testing.allocator;

    const enabled = std.process.getEnvVarOwned(allocator, "SYSLINK_NETWORK_E2E") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;

    const port = chooseTestPort();

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = port,
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    var wait_count: usize = 0;
    while (!server_ctx.ready.load(.acquire) and wait_count < 200) : (wait_count += 1) {
        std.Thread.sleep(5_000_000);
    }
    try testing.expect(server_ctx.ready.load(.acquire));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var prng = std.Random.DefaultPrng.init(0xfeed_beef);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", port, random);
    defer client.deinit();

    const authed = try client.authenticatePassword(USERNAME, PASSWORD);
    try testing.expect(authed);

    server_thread.join();
    try testing.expect(!server_ctx.failed.load(.acquire));
    try testing.expect(server_ctx.auth_ok.load(.acquire));
}
