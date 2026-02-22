const std = @import("std");
const runquic_transport = @import("runquic_transport");

/// LibLink adapter around runquic transport implementation.
///
/// Keeps third-party transport API coupling isolated to one file so upstream
/// runquic changes only require updates here.
pub const QuicTransport = struct {
    inner: runquic_transport.QuicTransport,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        socket: std.posix.socket_t,
        local_conn_id: []const u8,
        remote_conn_id: []const u8,
        client_secret: [32]u8,
        server_secret: [32]u8,
        is_server: bool,
        peer_addr: std.posix.sockaddr.storage,
    ) !Self {
        return Self{
            .inner = try runquic_transport.QuicTransport.init(
                allocator,
                socket,
                local_conn_id,
                remote_conn_id,
                client_secret,
                server_secret,
                is_server,
                peer_addr,
            ),
        };
    }

    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }

    pub fn openStream(self: *Self) !u64 {
        return self.inner.openStream();
    }

    pub fn closeStream(self: *Self, stream_id: u64) !void {
        return self.inner.closeStream(stream_id);
    }

    pub fn sendOnStream(self: *Self, stream_id: u64, data: []const u8) !void {
        return self.inner.sendOnStream(stream_id, data);
    }

    pub fn receiveFromStream(self: *Self, stream_id: u64, buffer: []u8) !usize {
        return self.inner.receiveFromStream(stream_id, buffer);
    }

    pub fn poll(self: *Self, timeout_ms: u32) !void {
        return self.inner.poll(timeout_ms);
    }
};

comptime {
    const T = runquic_transport.QuicTransport;
    if (!@hasDecl(T, "init") or !@hasDecl(T, "openStream") or !@hasDecl(T, "closeStream") or !@hasDecl(T, "sendOnStream") or !@hasDecl(T, "receiveFromStream") or !@hasDecl(T, "poll") or !@hasDecl(T, "deinit")) {
        @compileError("runquic_transport.QuicTransport no longer matches LibLink adapter expectations");
    }
}
