const std = @import("std");
const testing = std.testing;
const network_test_utils = @import("network_test_utils.zig");

const SERVER_PRNG_SEED: u64 = 0x1234_5678;
const CLIENT_PRNG_SEED: u64 = 0xfeed_beef;
const TEST_PORT_BASE: u16 = 38_000;

const ServerThreadCtx = struct {
    base: network_test_utils.CommonServerThreadCtx,
    auth_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var accepted = network_test_utils.startAndAcceptAuthenticatedServer(&ctx.base, SERVER_PRNG_SEED) catch {
        network_test_utils.markFailed(&ctx.base.failed);
        return;
    };
    defer accepted.deinit();

    ctx.auth_ok.store(true, .release);
}

test "Integration: network client/server password auth e2e" {
    const allocator = testing.allocator;

    try network_test_utils.requireEnvEnabled(allocator, "SYSLINK_NETWORK_E2E");

    const port = network_test_utils.chooseTestPort(TEST_PORT_BASE);

    var server_ctx = ServerThreadCtx{
        .base = .{
            .allocator = allocator,
            .port = port,
        },
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    try testing.expect(network_test_utils.waitForReadyFlag(
        &server_ctx.base.ready,
        network_test_utils.READY_WAIT_MAX_ATTEMPTS,
        network_test_utils.READY_WAIT_SLEEP_MS,
    ));
    try testing.expect(!server_ctx.base.failed.load(.acquire));

    var client = try network_test_utils.connectAuthenticatedClient(allocator, port, CLIENT_PRNG_SEED);
    defer client.deinit();

    server_thread.join();
    try testing.expect(!server_ctx.base.failed.load(.acquire));
    try testing.expect(server_ctx.auth_ok.load(.acquire));
}
