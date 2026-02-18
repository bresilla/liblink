const std = @import("std");
const syslink = @import("../../syslink.zig");

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
