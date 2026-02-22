const std = @import("std");
const crypto = std.crypto;

pub const public_key_size = 32;
pub const private_key_size = 32;
pub const shared_secret_size = 32;

pub const EcdhError = error{
    KeyExchangeFailed,
};

pub const KeyPair = struct {
    public_key: [public_key_size]u8,
    private_key: [private_key_size]u8,

    pub fn generate(random: std.Random) EcdhError!KeyPair {
        var private_key: [private_key_size]u8 = undefined;
        random.bytes(&private_key);

        const public_key = crypto.dh.X25519.recoverPublicKey(private_key) catch
            return error.KeyExchangeFailed;

        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }

    pub fn fromPrivateKey(private_key: [private_key_size]u8) EcdhError!KeyPair {
        const public_key = crypto.dh.X25519.recoverPublicKey(private_key) catch
            return error.KeyExchangeFailed;
        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }
};

pub fn exchange(
    private_key: *const [private_key_size]u8,
    peer_public_key: *const [public_key_size]u8,
) EcdhError![shared_secret_size]u8 {
    const shared = crypto.dh.X25519.scalarmult(
        private_key.*,
        peer_public_key.*,
    ) catch {
        return error.KeyExchangeFailed;
    };

    return shared;
}

test "X25519 key exchange" {
    const testing = std.testing;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    const alice = try KeyPair.generate(random);
    const bob = try KeyPair.generate(random);

    const alice_shared = try exchange(&alice.private_key, &bob.public_key);
    const bob_shared = try exchange(&bob.private_key, &alice.public_key);

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "X25519 RFC 7748 test vector" {
    const testing = std.testing;

    const alice_private = [_]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };

    const bob_public = [_]u8{
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };

    const expected_shared = [_]u8{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };

    const shared = try exchange(&alice_private, &bob_public);
    try testing.expectEqualSlices(u8, &expected_shared, &shared);
}
