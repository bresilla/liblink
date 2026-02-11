const std = @import("std");

// Re-export zcrypto for internal use
pub const zcrypto = @import("zcrypto");

// Re-export our crypto wrappers
pub const aead = @import("aead.zig");
pub const ecdh = @import("ecdh.zig");
pub const signature = @import("signature.zig");
pub const hash = @import("hash.zig");
pub const kdf = @import("kdf.zig");

test {
    // Include all submodule tests
    std.testing.refAllDecls(@This());
}
