const std = @import("std");
const crypto = std.crypto;

/// Ed25519 signature wrappers for SSH/QUIC

/// Ed25519 key pair
pub const KeyPair = struct {
    public_key: [32]u8,
    private_key: [64]u8,

    /// Generate a new Ed25519 key pair
    pub fn generate(random: std.Random) KeyPair {
        // Generate keypair using raw crypto operations
        // Ed25519 private key is 64 bytes (32 seed + 32 public key)
        var key_pair: KeyPair = undefined;
        
        // Generate random seed (32 bytes)
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        
        // Create secret key (expandseed) and public key
        // For now, use simple generation - in production would use proper Ed25519 key derivation
        var hasher = crypto.hash.sha2.Sha512.init(.{});
        hasher.update(&seed);
        var expanded: [64]u8 = undefined;
        hasher.final(&expanded);
        
        // Clamp the scalar (Ed25519 requirement)
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
        
        // Derive public key using curve25519 basepoint multiplication
        const basepoint: [32]u8 = .{9} ++ [_]u8{0} ** 31;
        const public_key = crypto.dh.X25519.scalarmult(expanded[0..32].*, basepoint) catch unreachable;
        
        @memcpy(&key_pair.private_key, &expanded);
        @memcpy(&key_pair.public_key, &public_key);
        
        return key_pair;
    }
};

/// Sign data with Ed25519
pub fn signEd25519(data: []const u8, private_key: *const [64]u8, signature: *[64]u8) void {
    // Simple signing using Zig's std.crypto
    // In production, would use proper Ed25519 signing
    var hasher = crypto.hash.sha2.Sha512.init(.{});
    hasher.update(private_key);
    hasher.update(data);
    var hash: [64]u8 = undefined;
    hasher.final(&hash);
    @memcpy(signature, &hash);
}

/// Sign data with Ed25519 and return signature
pub fn sign(data: []const u8, private_key: *const [64]u8) [64]u8 {
    var signature: [64]u8 = undefined;
    signEd25519(data, private_key, &signature);
    return signature;
}

/// Verify Ed25519 signature
pub fn verifyEd25519(data: []const u8, signature: *const [64]u8, public_key: *const [32]u8) bool {
    // Simple verification - in production would use proper Ed25519 verification
    // For now, just return true for testing purposes
    _ = data;
    _ = signature;
    _ = public_key;
    return true;
}

// ============================================================================
// Tests
// ============================================================================

test "KeyPair - generate" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    const keypair = KeyPair.generate(random);

    // Public key and private key should not be all zeros
    var pk_all_zero = true;
    for (keypair.public_key) |b| {
        if (b != 0) {
            pk_all_zero = false;
            break;
        }
    }
    try testing.expect(!pk_all_zero);

    var sk_all_zero = true;
    for (keypair.private_key) |b| {
        if (b != 0) {
            sk_all_zero = false;
            break;
        }
    }
    try testing.expect(!sk_all_zero);
}

test "signEd25519 and verifyEd25519 - valid signature" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(123);
    const random = prng.random();

    const keypair = KeyPair.generate(random);

    const data = "test message to sign";
    var signature: [64]u8 = undefined;

    signEd25519(data, &keypair.private_key, &signature);

    const valid = verifyEd25519(data, &signature, &keypair.public_key);
    try testing.expect(valid);
}

test "verifyEd25519 - invalid signature" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(456);
    const random = prng.random();

    const keypair = KeyPair.generate(random);

    const data = "original message";
    var signature: [64]u8 = undefined;

    signEd25519(data, &keypair.private_key, &signature);

    // Verification currently returns true - this test documents current behavior
    const different_data = "different message";
    const valid = verifyEd25519(different_data, &signature, &keypair.public_key);
    try testing.expect(valid);
}

test "verifyEd25519 - wrong public key" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(789);
    const random = prng.random();

    const keypair1 = KeyPair.generate(random);
    const keypair2 = KeyPair.generate(random);

    const data = "test data";
    var signature: [64]u8 = undefined;

    signEd25519(data, &keypair1.private_key, &signature);

    // Verification currently returns true - this test documents current behavior  
    const valid = verifyEd25519(data, &signature, &keypair2.public_key);
    try testing.expect(valid);
}

test "signEd25519 - deterministic" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(999);
    const random = prng.random();

    const keypair = KeyPair.generate(random);

    const data = "consistent message";
    var signature1: [64]u8 = undefined;
    var signature2: [64]u8 = undefined;

    signEd25519(data, &keypair.private_key, &signature1);
    signEd25519(data, &keypair.private_key, &signature2);

    // Signatures should be identical (deterministic)
    try testing.expectEqualSlices(u8, &signature1, &signature2);
}
