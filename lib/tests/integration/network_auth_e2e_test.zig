const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");
const network_test_utils = @import("network_test_utils.zig");

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

    const host_key_blob = network_test_utils.encodeHostKeyBlob(ctx.allocator, &ed_keypair.public_key.bytes) catch {
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

    const ok = server_conn.handleAuthentication(network_test_utils.validatePassword, null) catch {
        ctx.failed.store(true, .release);
        return;
    };
    ctx.auth_ok.store(ok, .release);
}

test "Integration: network client/server password auth e2e" {
    const allocator = testing.allocator;

    try network_test_utils.requireEnvEnabled(allocator, "SYSLINK_NETWORK_E2E");

    const port = network_test_utils.chooseTestPort(38000);

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = port,
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    try testing.expect(network_test_utils.waitForReadyFlag(&server_ctx.ready, 200, 5));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var prng = std.Random.DefaultPrng.init(0xfeed_beef);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", port, random);
    defer client.deinit();

    const authed = try client.authenticatePassword(network_test_utils.USERNAME, network_test_utils.PASSWORD);
    try testing.expect(authed);

    server_thread.join();
    try testing.expect(!server_ctx.failed.load(.acquire));
    try testing.expect(server_ctx.auth_ok.load(.acquire));
}
