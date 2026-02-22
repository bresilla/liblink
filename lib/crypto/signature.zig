const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;

/// Ed25519 signature wrappers for SSH/QUIC

/// Ed25519 key pair
pub const KeyPair = struct {
    public_key: [32]u8,
    private_key: [64]u8,

    /// Generate a new Ed25519 key pair
    ///
    /// Note: For testing only. Use proper key generation in production.
    pub fn generate(random: std.Random) KeyPair {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        random.bytes(&seed);
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
        return .{
            .public_key = kp.public_key.bytes,
            .private_key = kp.secret_key.bytes,
        };
    }
};

/// Sign data with Ed25519
pub fn signEd25519(data: []const u8, private_key: *const [64]u8, signature: *[64]u8) void {
    const public_bytes = private_key[32..64];

    const key_pair = Ed25519.KeyPair{
        .public_key = Ed25519.PublicKey{ .bytes = public_bytes.* },
        .secret_key = Ed25519.SecretKey{ .bytes = private_key.* },
    };

    const sig = key_pair.sign(data, null) catch unreachable;
    @memcpy(signature, &sig.toBytes());
}

/// Sign data with Ed25519 and return signature
pub fn sign(data: []const u8, private_key: *const [64]u8) [64]u8 {
    var signature: [64]u8 = undefined;
    signEd25519(data, private_key, &signature);
    return signature;
}

/// Verify Ed25519 signature
pub fn verifyEd25519(data: []const u8, signature: *const [64]u8, public_key: *const [32]u8) bool {
    const sig = Ed25519.Signature.fromBytes(signature.*);
    const pubkey = Ed25519.PublicKey{ .bytes = public_key.* };
    sig.verify(data, pubkey) catch {
        return false;
    };
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

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const keypair = KeyPair.generate(random);

    const data = "test message";
    var signature: [64]u8 = undefined;
    signEd25519(data, &keypair.private_key, &signature);

    try testing.expect(verifyEd25519(data, &signature, &keypair.public_key));
}

test "verifyEd25519 - invalid signature" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const keypair = KeyPair.generate(random);

    const data = "test message";
    var signature: [64]u8 = undefined;
    signEd25519(data, &keypair.private_key, &signature);

    // Corrupt the signature
    signature[0] ^= 0xFF;
    try testing.expect(!verifyEd25519(data, &signature, &keypair.public_key));
}

test "verifyEd25519 - wrong public key" {
    const testing = std.testing;

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const keypair1 = KeyPair.generate(random);
    const keypair2 = KeyPair.generate(random);

    const data = "test message";
    var signature: [64]u8 = undefined;
    signEd25519(data, &keypair1.private_key, &signature);

    // Verify with wrong public key should fail
    try testing.expect(!verifyEd25519(data, &signature, &keypair2.public_key));
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
