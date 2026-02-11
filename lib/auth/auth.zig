const std = @import("std");

/// SSH authentication methods

pub const password = @import("password.zig");

test {
    std.testing.refAllDecls(@This());
}
