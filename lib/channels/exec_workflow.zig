const std = @import("std");
const SessionChannel = @import("session.zig").SessionChannel;
const channel_protocol = @import("../protocol/channel.zig");

pub const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    exit_status: ?u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ExecResult) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
    }
};

/// Collect exec output from a session channel until EOF/CLOSE.
/// Returns aggregated stdout, stderr, and optional exit-status.
pub fn collectExecResult(
    allocator: std.mem.Allocator,
    session: *SessionChannel,
    poll_timeout_ms: u32,
) !ExecResult {
    var stdout_buf: std.ArrayList(u8) = .empty;
    errdefer stdout_buf.deinit(allocator);

    var stderr_buf: std.ArrayList(u8) = .empty;
    errdefer stderr_buf.deinit(allocator);

    var exit_status: ?u32 = null;
    var buffer: [65536]u8 = undefined;

    while (true) {
        session.manager.transport.poll(poll_timeout_ms) catch {};

        const len = session.manager.transport.receiveFromStream(session.stream_id, &buffer) catch |err| {
            if (err == error.NoData) continue;
            if (err == error.EndOfStream) break;
            return err;
        };
        if (len == 0) continue;

        const packet = buffer[0..len];
        if (packet.len == 0) continue;

        switch (packet[0]) {
            94 => {
                var msg = try channel_protocol.ChannelData.decode(allocator, packet);
                defer msg.deinit(allocator);
                try stdout_buf.appendSlice(allocator, msg.data);
            },
            95 => {
                var msg = try channel_protocol.ChannelExtendedData.decode(allocator, packet);
                defer msg.deinit(allocator);
                if (msg.data_type_code == 1) {
                    try stderr_buf.appendSlice(allocator, msg.data);
                } else {
                    try stdout_buf.appendSlice(allocator, msg.data);
                }
            },
            98 => {
                var req = try channel_protocol.ChannelRequest.decode(allocator, packet);
                defer req.deinit(allocator);
                if (std.mem.eql(u8, req.request_type, "exit-status") and req.type_specific_data.len >= 4) {
                    exit_status = std.mem.readInt(u32, req.type_specific_data[0..4], .big);
                }
            },
            96, 97 => break,
            else => {},
        }
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_status = exit_status,
        .allocator = allocator,
    };
}
