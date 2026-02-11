const std = @import("std");

/// SSH authentication methods

pub const password = @import("password.zig");
pub const publickey = @import("publickey.zig");

test {
    std.testing.refAllDecls(@This());
}
