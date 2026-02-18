const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");
const network_test_utils = @import("network_test_utils.zig");

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

fn chooseTestPort() u16 {
    const ts: u64 = @intCast(std.time.nanoTimestamp());
    const base: u16 = 40000;
    return base + @as(u16, @intCast(ts % 2000));
}

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
    defer listener.removeConnection(server_conn);

    const auth_ok = server_conn.handleAuthentication(validatePassword, null) catch {
        ctx.failed.store(true, .release);
        return;
    };
    if (!auth_ok) {
        ctx.failed.store(true, .release);
        return;
    }

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

    const enabled = std.process.getEnvVarOwned(allocator, "SYSLINK_NETWORK_SFTP_E2E") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;

    const tmp_root = try std.fmt.allocPrint(allocator, "/tmp/syslink-net-sftp-e2e-{}", .{std.time.nanoTimestamp()});
    defer allocator.free(tmp_root);
    defer std.fs.cwd().deleteTree(tmp_root) catch {};
    try std.fs.cwd().makePath(tmp_root);

    var server_ctx = ServerThreadCtx{
        .allocator = allocator,
        .port = chooseTestPort(),
        .remote_root = tmp_root,
    };

    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&server_ctx});

    var wait_count: usize = 0;
    while (!server_ctx.ready.load(.acquire) and wait_count < 200) : (wait_count += 1) {
        std.Thread.sleep(5_000_000);
    }
    try testing.expect(server_ctx.ready.load(.acquire));
    try testing.expect(!server_ctx.failed.load(.acquire));

    var prng = std.Random.DefaultPrng.init(0x1357_2468);
    const random = prng.random();

    var client = try syslink.connection.connectClient(allocator, "127.0.0.1", server_ctx.port, random);
    defer client.deinit();

    const authed = try client.authenticatePassword(USERNAME, PASSWORD);
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
