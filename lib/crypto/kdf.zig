const std = @import("std");
const crypto = std.crypto;

/// HMAC-SHA256 output size (32 bytes)
pub const hmac_sha256_size = 32;

/// HKDF-SHA256 minimum and maximum output sizes
pub const hkdf_min_size = 1;
pub const hkdf_max_size = 255 * 32; // 255 * hash_len per RFC 5869

/// Errors for KDF operations
pub const KdfError = error{
    OutputTooLarge,
    InvalidKeyLength,
};

/// Compute HMAC-SHA256
///
/// Parameters:
/// - key: Secret key for HMAC
/// - message: Data to authenticate
/// - out: Output buffer for HMAC (must be 32 bytes)
pub fn hmacSha256(key: []const u8, message: []const u8, out: *[hmac_sha256_size]u8) void {
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(message);
    hmac.final(out);
}

/// HKDF-SHA256 Extract step
///
/// Extracts a pseudorandom key from input key material
///
/// Parameters:
/// - salt: Optional salt value (can be empty for default zero salt)
/// - ikm: Input key material
/// - prk: Output pseudorandom key (32 bytes)
fn hkdfExtract(salt: []const u8, ikm: []const u8, prk: *[hmac_sha256_size]u8) void {
    const actual_salt = if (salt.len == 0) &([_]u8{0} ** hmac_sha256_size) else salt;
    hmacSha256(actual_salt, ikm, prk);
}

/// HKDF-SHA256 Expand step
///
/// Expands a pseudorandom key to desired length
///
/// Parameters:
/// - prk: Pseudorandom key from extract step (32 bytes)
/// - info: Optional context/application specific info
/// - out: Output buffer for expanded key material
fn hkdfExpand(prk: *const [hmac_sha256_size]u8, info: []const u8, out: []u8) KdfError!void {
    if (out.len > hkdf_max_size) {
        return error.OutputTooLarge;
    }

    const n = (out.len + hmac_sha256_size - 1) / hmac_sha256_size;
    var t_prev: [hmac_sha256_size]u8 = undefined;
    var offset: usize = 0;

    for (0..n) |i| {
        var hmac = crypto.auth.hmac.sha2.HmacSha256.init(prk);

        // T(i) = HMAC(PRK, T(i-1) | info | i)
        if (i > 0) {
            hmac.update(&t_prev);
        }
        hmac.update(info);
        const counter = @as(u8, @intCast(i + 1));
        hmac.update(&[_]u8{counter});

        hmac.final(&t_prev);

        // Copy to output
        const remaining = out.len - offset;
        const to_copy = @min(hmac_sha256_size, remaining);
        @memcpy(out[offset..][0..to_copy], t_prev[0..to_copy]);
        offset += to_copy;
    }
}

/// HKDF-SHA256 (RFC 5869)
///
/// Full HKDF key derivation: Extract then Expand
///
/// Parameters:
/// - ikm: Input key material (the shared secret)
/// - salt: Optional salt value (use empty for default)
/// - info: Optional context/application specific info
/// - out: Output buffer for derived key material
pub fn hkdfSha256(ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) KdfError!void {
    var prk: [hmac_sha256_size]u8 = undefined;
    hkdfExtract(salt, ikm, &prk);
    try hkdfExpand(&prk, info, out);
}

// ============================================================================
// Tests
// ============================================================================

test "HMAC-SHA256 empty key and message" {
    const testing = std.testing;

    var mac: [hmac_sha256_size]u8 = undefined;
    hmacSha256("", "", &mac);

    // HMAC-SHA256("", "") per test vectors
    const expected = [_]u8{
        0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec,
        0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
        0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
        0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad,
    };

    try testing.expectEqualSlices(u8, &expected, &mac);
}

test "HMAC-SHA256 with key and message" {
    const testing = std.testing;

    const key = "key";
    const message = "The quick brown fox jumps over the lazy dog";
    var mac: [hmac_sha256_size]u8 = undefined;
    hmacSha256(key, message, &mac);

    // HMAC-SHA256 test vector
    const expected = [_]u8{
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
    };

    try testing.expectEqualSlices(u8, &expected, &mac);
}

test "HKDF-SHA256 RFC 5869 Test Case 1" {
    const testing = std.testing;

    const ikm = [_]u8{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm: [42]u8 = undefined;
    try hkdfSha256(&ikm, &salt, &info, &okm);

    const expected = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };

    try testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA256 RFC 5869 Test Case 3" {
    const testing = std.testing;

    // Test Case 3: Empty salt and info
    const ikm = [_]u8{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    var okm: [42]u8 = undefined;
    try hkdfSha256(&ikm, "", "", &okm);

    const expected = [_]u8{
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
        0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
        0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
        0x96, 0xc8,
    };

    try testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA256 with empty salt" {
    const testing = std.testing;

    const ikm = "input key material";
    const info = "context info";

    var okm: [32]u8 = undefined;
    try hkdfSha256(ikm, "", info, &okm);

    // Verify output is not all zeros
    var all_zero = true;
    for (okm) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "HKDF-SHA256 output too large" {
    const testing = std.testing;

    const ikm = "key";
    var okm: [hkdf_max_size + 1]u8 = undefined;

    try testing.expectError(error.OutputTooLarge, hkdfSha256(ikm, "", "", &okm));
}
