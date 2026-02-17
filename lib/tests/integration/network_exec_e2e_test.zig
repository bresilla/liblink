const std = @import("std");
const testing = std.testing;
const syslink = @import("../../syslink.zig");

const USERNAME = "e2e-user";
const PASSWORD = "e2e-pass";
const EXPECTED_COMMAND = "printf deterministic-exec";

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
    const base: u16 = 42000;
    return base + @as(u16, @intCast(ts % 2000));
}

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

    tryHandleExecSession(server_conn) catch {
        ctx.failed.store(true, .release);
        return;
    };
}

fn tryHandleExecSession(server_conn: *syslink.connection.ServerConnection) !void {
    try server_conn.transport.poll(30000);
    try server_conn.channel_manager.acceptChannel(4);

    var request_buf: [4096]u8 = undefined;
    while (true) {
        try server_conn.transport.poll(30000);
        const len = try server_conn.transport.receiveFromStream(4, &request_buf);
        if (len == 0) continue;

        var req = try server_conn.channel_manager.handleRequest(4, request_buf[0..len]);
        defer req.deinit(server_conn.allocator);

        if (!std.mem.eql(u8, req.request.request_type, "exec")) {
            try server_conn.channel_manager.sendFailure(4);
            continue;
        }

        var reader = syslink.protocol.wire.Reader{ .buffer = req.request.type_specific_data };
        const command = try reader.readString(server_conn.allocator);
        defer server_conn.allocator.free(command);
        if (!std.mem.eql(u8, command, EXPECTED_COMMAND)) {
            return error.UnexpectedCommand;
        }

        try server_conn.channel_manager.sendSuccess(4);
        break;
    }

    try server_conn.channel_manager.sendData(4, "stdout-part-1 ");
    try server_conn.channel_manager.sendData(4, "stdout-part-2\n");
    try server_conn.channel_manager.sendExtendedData(4, 1, "stderr-part\n");

    var status_data: [4]u8 = undefined;
    std.mem.writeInt(u32, &status_data, 23, .big);
    try server_conn.channel_manager.sendRequest(4, "exit-status", false, &status_data);

    try server_conn.channel_manager.sendEof(4);
    try server_conn.channel_manager.closeChannel(4);
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
        .port = chooseTestPort(),
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

    const authed = try client.authenticatePassword(USERNAME, PASSWORD);
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
