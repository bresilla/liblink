const std = @import("std");
const kdf = @import("../crypto/kdf.zig");

/// Derive QUIC secrets from SSH key exchange
/// Per SPEC.md Section 5.1: QUIC Session Setup
///
/// After SSH key exchange produces:
/// - K: shared secret (mpint)
/// - H: exchange hash (binary data)
///
/// We derive:
/// - client_secret = HMAC-SHA256("ssh/quic client", secret_data)
/// - server_secret = HMAC-SHA256("ssh/quic server", secret_data)
///
/// Where secret_data = mpint(K) || string(H)

pub const QuicSecrets = struct {
    client_secret: [32]u8,
    server_secret: [32]u8,
};

/// Derive QUIC client and server secrets from SSH key exchange outputs
///
/// Parameters:
/// - shared_secret_k: SSH shared secret K (raw bytes, will be encoded as mpint)
/// - exchange_hash_h: SSH exchange hash H (raw bytes, will be encoded as string)
/// - allocator: Memory allocator for temporary encoding buffer
pub fn deriveQuicSecrets(
    shared_secret_k: []const u8,
    exchange_hash_h: []const u8,
    allocator: std.mem.Allocator,
) !QuicSecrets {
    // Encode secret_data = mpint(K) || string(H)
    const secret_data = try encodeSecretData(shared_secret_k, exchange_hash_h, allocator);
    defer allocator.free(secret_data);

    var secrets: QuicSecrets = undefined;

    // client_secret = HMAC-SHA256("ssh/quic client", secret_data)
    kdf.hmacSha256("ssh/quic client", secret_data, &secrets.client_secret);

    // server_secret = HMAC-SHA256("ssh/quic server", secret_data)
    kdf.hmacSha256("ssh/quic server", secret_data, &secrets.server_secret);

    return secrets;
}

/// Encode secret_data = mpint(K) || string(H)
///
/// SSH wire encoding:
/// - mpint: 4-byte length || data (with leading zeros removed, but sign bit handled)
/// - string: 4-byte length || data
fn encodeSecretData(
    k: []const u8,
    h: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    // Calculate total size: mpint(K) + string(H)
    // mpint: 4 bytes length + K data
    // string: 4 bytes length + H data
    const size = 4 + k.len + 4 + h.len;
    var buffer = try allocator.alloc(u8, size);

    var offset: usize = 0;

    // Encode mpint(K)
    // Length in network byte order (big-endian)
    std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(k.len), .big);
    offset += 4;
    @memcpy(buffer[offset..][0..k.len], k);
    offset += k.len;

    // Encode string(H)
    std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(h.len), .big);
    offset += 4;
    @memcpy(buffer[offset..][0..h.len], h);

    return buffer;
}

// ============================================================================
// Tests
// ============================================================================

test "encodeSecretData basic" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const k = [_]u8{ 0xAA, 0xBB, 0xCC };
    const h = [_]u8{ 0x11, 0x22 };

    const encoded = try encodeSecretData(&k, &h, allocator);
    defer allocator.free(encoded);

    // Expected: mpint(K) || string(H)
    // mpint(K): 0x00000003 || 0xAABBCC
    // string(H): 0x00000002 || 0x1122
    const expected = [_]u8{
        0x00, 0x00, 0x00, 0x03, // length of K
        0xAA, 0xBB, 0xCC, // K
        0x00, 0x00, 0x00, 0x02, // length of H
        0x11, 0x22, // H
    };

    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "deriveQuicSecrets produces different secrets" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const k = [_]u8{0xAA} ** 32;
    const h = [_]u8{0xBB} ** 32;

    const secrets = try deriveQuicSecrets(&k, &h, allocator);

    // client_secret and server_secret should be different
    try testing.expect(!std.mem.eql(u8, &secrets.client_secret, &secrets.server_secret));

    // Secrets should not be all zeros
    var all_zero = true;
    for (secrets.client_secret) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "deriveQuicSecrets is deterministic" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const k = [_]u8{0xCC} ** 32;
    const h = [_]u8{0xDD} ** 32;

    const secrets1 = try deriveQuicSecrets(&k, &h, allocator);
    const secrets2 = try deriveQuicSecrets(&k, &h, allocator);

    // Same inputs should produce same outputs
    try testing.expectEqualSlices(u8, &secrets1.client_secret, &secrets2.client_secret);
    try testing.expectEqualSlices(u8, &secrets1.server_secret, &secrets2.server_secret);
}
