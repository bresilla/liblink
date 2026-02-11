const std = @import("std");

// Import our modules
pub const protocol = struct {
    pub const wire = @import("protocol/wire.zig");
    pub const random = @import("protocol/random.zig");
    pub const obfuscation = @import("protocol/obfuscation.zig");
    pub const kex_init = @import("protocol/kex_init.zig");
    pub const kex_reply = @import("protocol/kex_reply.zig");
    pub const kex_cancel = @import("protocol/kex_cancel.zig");
    pub const kex_curve25519 = @import("protocol/kex_curve25519.zig");
    pub const key_derivation = @import("protocol/key_derivation.zig");
    pub const ssh_packet = @import("protocol/ssh_packet.zig");
    pub const quic_streams = @import("protocol/quic_streams.zig");
};

pub const common = struct {
    pub const errors = @import("common/errors.zig");
    pub const constants = @import("common/constants.zig");
};

pub const crypto = @import("crypto/crypto.zig");

test {
    std.testing.refAllDecls(@This());
}
