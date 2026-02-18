const std = @import("std");
const syslink = @import("../../syslink.zig");

pub const USERNAME = "e2e-user";
pub const PASSWORD = "e2e-pass";

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
