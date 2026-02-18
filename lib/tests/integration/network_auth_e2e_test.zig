const std = @import("std");
const testing = std.testing;
const network_test_utils = @import("network_test_utils.zig");

const ServerThreadCtx = struct {
    base: network_test_utils.CommonServerThreadCtx,
    auth_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const random = prng.random();

    var server = network_test_utils.startLocalTestServer(ctx.base.allocator, ctx.base.port, random) catch {
        network_test_utils.markFailed(&ctx.base.failed);
        return;
    };
    defer server.deinit();

    ctx.base.ready.store(true, .release);

    const server_conn = network_test_utils.acceptAuthenticatedConnection(&server.listener) catch {
        network_test_utils.markFailed(&ctx.base.failed);
        return;
    };
    defer {
        server.listener.removeConnection(server_conn);
    }

    ctx.auth_ok.store(true, .release);
}

test "Integration: network client/server password auth e2e" {
    const allocator = testing.allocator;

    try network_test_utils.requireEnvEnabled(allocator, "SYSLINK_NETWORK_E2E");

    const port = network_test_utils.chooseTestPort(38000);

    var server_ctx = ServerThreadCtx{
        .base = .{
            .allocator = allocator,
            .port = port,
        },
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    try testing.expect(network_test_utils.waitForReadyFlag(&server_ctx.base.ready, 200, 5));
    try testing.expect(!server_ctx.base.failed.load(.acquire));

    var client = try network_test_utils.connectAuthenticatedClient(allocator, port, 0xfeed_beef);
    defer client.deinit();

    server_thread.join();
    try testing.expect(!server_ctx.base.failed.load(.acquire));
    try testing.expect(server_ctx.auth_ok.load(.acquire));
}
