const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");
const network_test_utils = @import("network_test_utils.zig");

const ServerThreadCtx = struct {
    allocator: std.mem.Allocator,
    port: u16,
    remote_root: []const u8,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn serverThreadMain(ctx: *ServerThreadCtx) void {
    var prng = std.Random.DefaultPrng.init(0x9abc_def0);
    const random = prng.random();

    var server = network_test_utils.startLocalTestServer(ctx.allocator, ctx.port, random) catch {
        ctx.failed.store(true, .release);
        return;
    };
    defer server.deinit();

    ctx.ready.store(true, .release);

    const server_conn = network_test_utils.acceptAuthenticatedConnection(&server.listener) catch {
        ctx.failed.store(true, .release);
        return;
    };
    defer server.listener.removeConnection(server_conn);

    tryHandleSftpSession(server_conn, ctx.remote_root) catch {
        ctx.failed.store(true, .release);
        return;
    };
}

fn tryHandleSftpSession(server_conn: *syslink.connection.ServerConnection, remote_root: []const u8) !void {
    const stream_id = try network_test_utils.waitForSessionChannel(server_conn, 30000);

    var request_buf: [4096]u8 = undefined;
    while (true) {
        try server_conn.transport.poll(30000);
        const len = try server_conn.transport.receiveFromStream(stream_id, &request_buf);
        if (len == 0) continue;

        var req = try server_conn.channel_manager.handleRequest(stream_id, request_buf[0..len]);
        defer req.deinit(server_conn.allocator);

        if (!std.mem.eql(u8, req.request.request_type, "subsystem")) {
            try server_conn.channel_manager.sendFailure(stream_id);
            continue;
        }

        var reader = syslink.protocol.wire.Reader{ .buffer = req.request.type_specific_data };
        const subsystem_name = try reader.readString(server_conn.allocator);
        defer server_conn.allocator.free(subsystem_name);

        if (!std.mem.eql(u8, subsystem_name, "sftp")) {
            try server_conn.channel_manager.sendFailure(stream_id);
            return error.UnsupportedSubsystem;
        }

        try server_conn.channel_manager.sendSuccess(stream_id);
        break;
    }

    const session_channel = syslink.channels.SessionChannel{
        .manager = &server_conn.channel_manager,
        .stream_id = stream_id,
        .allocator = server_conn.allocator,
    };
    const sftp_channel = syslink.sftp.SftpChannel.init(server_conn.allocator, session_channel);
    var sftp_server = try syslink.sftp.SftpServer.initWithOptions(server_conn.allocator, sftp_channel, .{
        .remote_root = remote_root,
    });
    defer sftp_server.deinit();

    sftp_server.run() catch |err| {
        if (err != error.EndOfStream and err != error.ConnectionClosed) return err;
    };
}

test "Integration: network SFTP subsystem e2e" {
    const allocator = testing.allocator;

    try network_test_utils.requireEnvEnabled(allocator, "SYSLINK_NETWORK_SFTP_E2E");

    const tmp_root = try std.fmt.allocPrint(allocator, "/tmp/syslink-net-sftp-e2e-{}", .{std.time.nanoTimestamp()});
    defer allocator.free(tmp_root);
    defer std.fs.cwd().deleteTree(tmp_root) catch {};
    try std.fs.cwd().makePath(tmp_root);

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = network_test_utils.chooseTestPort(40000),
        .remote_root = tmp_root,
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    try testing.expect(network_test_utils.waitForReadyFlag(&server_ctx.ready, 200, 5));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var prng = std.Random.DefaultPrng.init(0x1357_2468);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", server_ctx.port, random);
    defer client.deinit();

    const authed = try client.authenticatePassword(network_test_utils.USERNAME, network_test_utils.PASSWORD);
    try testing.expect(authed);

    var sftp_channel = try client.openSftp();
    defer sftp_channel.getSession().close() catch {};

    var sftp_client = try syslink.sftp.SftpClient.init(allocator, sftp_channel);
    defer sftp_client.deinit();

    try sftp_client.mkdir("/docs", syslink.sftp.attributes.FileAttributes.init());

    const open_flags = syslink.sftp.protocol.OpenFlags{ .read = true, .write = true, .creat = true, .trunc = true };
    var handle = try sftp_client.open("/docs/hello.txt", open_flags, syslink.sftp.attributes.FileAttributes.init());
    defer handle.deinit(allocator);

    try sftp_client.write(handle, 0, "hello-net-sftp");
    const data = try sftp_client.read(handle, 0, 14);
    defer allocator.free(data);
    try testing.expectEqualStrings("hello-net-sftp", data);

    try sftp_client.close(handle);
    try sftp_client.rename("/docs/hello.txt", "/docs/renamed.txt");
    try sftp_client.remove("/docs/renamed.txt");
    try sftp_client.rmdir("/docs");

    server_thread.join();
    try testing.expect(!server_ctx.failed.load(.acquire));
}
