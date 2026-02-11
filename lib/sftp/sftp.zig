const std = @import("std");

/// SFTP (SSH File Transfer Protocol) subsystem

pub const protocol = @import("protocol.zig");

test {
    std.testing.refAllDecls(@This());
}
