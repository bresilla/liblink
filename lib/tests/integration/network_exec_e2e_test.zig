const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");
const network_test_utils = @import("network_test_utils.zig");

const EXPECTED_COMMAND = "printf deterministic-exec";

const ServerThreadCtx = network_test_utils.CommonServerThreadCtx;

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var prng = std.Random.DefaultPrng.init(0x2468_1357);
    const random = prng.random();

    var server = network_test_utils.startLocalTestServer(ctx.allocator, ctx.port, random) catch {
        network_test_utils.markFailed(&ctx.failed);
        return;
    };
    defer server.deinit();

    ctx.ready.store(true, .release);

    const server_conn = network_test_utils.acceptAuthenticatedConnection(&server.listener) catch {
        network_test_utils.markFailed(&ctx.failed);
        return;
    };
    defer server.listener.removeConnection(server_conn);

    tryHandleExecSession(server_conn) catch {
        network_test_utils.markFailed(&ctx.failed);
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

    try network_test_utils.requireEnvEnabled(allocator, "SYSLINK_NETWORK_EXEC_E2E");

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = network_test_utils.chooseTestPort(42000),
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    try testing.expect(network_test_utils.waitForReadyFlag(&server_ctx.ready, 200, 5));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var client = try network_test_utils.connectAuthenticatedClient(allocator, server_ctx.port, 0xdead_babe);
    defer client.deinit();

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
