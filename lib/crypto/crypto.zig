const std = @import("std");

// Re-export std.crypto for convenience
pub const std_crypto = std.crypto;

// Re-export our crypto wrappers
pub const aead = @import("aead.zig");

// Placeholders for future implementation
pub const ecdh = struct {};
pub const signature = struct {};
pub const hash = struct {};
pub const kdf = struct {};

test {
    // Include all submodule tests
    std.testing.refAllDecls(@This());
}
