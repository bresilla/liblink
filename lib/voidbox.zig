const std = @import("std");

// Import our modules
pub const protocol = struct {
    pub const wire = @import("protocol/wire.zig");
    pub const random = @import("protocol/random.zig");
    pub const obfuscation = @import("protocol/obfuscation.zig");
    pub const kex_init = @import("protocol/kex_init.zig");
    pub const kex_reply = @import("protocol/kex_reply.zig");
    pub const kex_cancel = @import("protocol/kex_cancel.zig");
};

pub const common = struct {
    pub const errors = @import("common/errors.zig");
    pub const constants = @import("common/constants.zig");
};

pub const crypto = @import("crypto/crypto.zig");

test {
    std.testing.refAllDecls(@This());
}
