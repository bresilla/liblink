const std = @import("std");

// Re-export std.crypto for convenience
pub const std_crypto = std.crypto;

// Re-export our crypto wrappers
pub const aead = @import("aead.zig");
pub const ecdh = @import("ecdh.zig");
pub const hash = @import("hash.zig");
pub const kdf = @import("kdf.zig");
pub const signature = @import("signature.zig");

test {
    // Include all submodule tests
    std.testing.refAllDecls(@This());
}
