const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");
const network_test_utils = @import("network_test_utils.zig");

const EXPECTED_COMMAND = "printf deterministic-exec";

const ServerThreadCtx = struct {
    allocator: std.mem.Allocator,
    port: u16,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var prng = std.Random.DefaultPrng.init(0x2468_1357);
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
    defer listener.removeConnection(server_conn);

    const auth_ok = server_conn.handleAuthentication(network_test_utils.validatePassword, null) catch {
        ctx.failed.store(true, .release);
        return;
    };
    if (!auth_ok) {
        ctx.failed.store(true, .release);
        return;
    }

    tryHandleExecSession(server_conn) catch {
        ctx.failed.store(true, .release);
        return;
    };
}

fn tryHandleExecSession(server_conn: *syslink.connection.ServerConnection) !void {
    const stream_id = try network_test_utils.waitForSessionChannel(server_conn, 30000);

    var request_buf: [4096]u8 = undefined;
    while (true) {
        try server_conn.transport.poll(30000);
        const len = try server_conn.transport.receiveFromStream(stream_id, &request_buf);
        if (len == 0) continue;

        var req = try server_conn.channel_manager.handleRequest(stream_id, request_buf[0..len]);
        defer req.deinit(server_conn.allocator);

        if (!std.mem.eql(u8, req.request.request_type, "exec")) {
            try server_conn.channel_manager.sendFailure(stream_id);
            continue;
        }

        var reader = syslink.protocol.wire.Reader{ .buffer = req.request.type_specific_data };
        const command = try reader.readString(server_conn.allocator);
        defer server_conn.allocator.free(command);
        if (!std.mem.eql(u8, command, EXPECTED_COMMAND)) {
            return error.UnexpectedCommand;
        }

        try server_conn.channel_manager.sendSuccess(stream_id);
        break;
    }

    try server_conn.channel_manager.sendData(stream_id, "stdout-part-1 ");
    try server_conn.channel_manager.sendData(stream_id, "stdout-part-2\n");
    try server_conn.channel_manager.sendExtendedData(stream_id, 1, "stderr-part\n");

    var status_data: [4]u8 = undefined;
    std.mem.writeInt(u32, &status_data, 23, .big);
    try server_conn.channel_manager.sendRequest(stream_id, "exit-status", false, &status_data);

    try server_conn.channel_manager.sendEof(stream_id);
    try server_conn.channel_manager.closeChannel(stream_id);
}

test "Integration: network exec e2e returns stdout stderr and exit-status" {
    const allocator = testing.allocator;

    const enabled = std.process.getEnvVarOwned(allocator, "SYSLINK_NETWORK_EXEC_E2E") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = network_test_utils.chooseTestPort(42000),
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    var wait_count: usize = 0;
    while (!server_ctx.ready.load(.acquire) and wait_count < 200) : (wait_count += 1) {
        std.Thread.sleep(5_000_000);
    }
    try testing.expect(server_ctx.ready.load(.acquire));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var prng = std.Random.DefaultPrng.init(0xdead_babe);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", server_ctx.port, random);
    defer client.deinit();

    const authed = try client.authenticatePassword(network_test_utils.USERNAME, network_test_utils.PASSWORD);
    try testing.expect(authed);

    var session = try client.requestExec(EXPECTED_COMMAND);
    defer session.close() catch {};

    var result = try syslink.channels.collectExecResult(allocator, &session, 5000);
    defer result.deinit();

    try testing.expectEqualStrings("stdout-part-1 stdout-part-2\n", result.stdout);
    try testing.expectEqualStrings("stderr-part\n", result.stderr);
    try testing.expectEqual(@as(?u32, 23), result.exit_status);

    server_thread.join();
    try testing.expect(!server_ctx.failed.load(.acquire));
}
