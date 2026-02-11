const std = @import("std");

// Placeholder for Ed25519 signatures - will implement with full API later
pub const public_key_size = 32;
pub const secret_key_size = 64;
pub const signature_size = 64;

pub const SignatureError = error{
    SignatureVerificationFailed,
    NotImplemented,
};

// TODO: Implement full Ed25519 wrapper when needed for host key verification
pub fn sign(
    message: []const u8,
    secret_key: *const [secret_key_size]u8,
) [signature_size]u8 {
    _ = message;
    _ = secret_key;
    return [_]u8{0} ** signature_size;
}

pub fn verify(
    message: []const u8,
    signature: *const [signature_size]u8,
    public_key: *const [public_key_size]u8,
) SignatureError!void {
    _ = message;
    _ = signature;
    _ = public_key;
    return error.NotImplemented;
}
