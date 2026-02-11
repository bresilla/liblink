const std = @import("std");
const crypto = std.crypto;

/// AES-256-GCM nonce size (96 bits / 12 bytes is standard for GCM)
pub const nonce_size = 12;

/// AES-256-GCM authentication tag size
pub const tag_size = 16;

/// AES-256-GCM key size
pub const key_size = 32;

/// Errors for AEAD operations
pub const AeadError = error{
    AuthenticationFailed,
    InvalidKeySize,
    InvalidNonceSize,
};

/// Encrypt data using AES-256-GCM
///
/// Parameters:
/// - key: 32-byte encryption key
/// - nonce: 12-byte nonce (must be unique for each encryption with same key)
/// - plaintext: Data to encrypt
/// - ciphertext: Output buffer (must be same length as plaintext)
/// - tag: Output buffer for authentication tag (16 bytes)
/// - associated_data: Additional authenticated data (can be empty)
pub fn encrypt(
    key: *const [key_size]u8,
    nonce: *const [nonce_size]u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[tag_size]u8,
    associated_data: []const u8,
) AeadError!void {
    if (ciphertext.len < plaintext.len) {
        return error.InvalidKeySize; // Reusing error for buffer size
    }

    // Use std.crypto's AES-256-GCM implementation
    crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        ciphertext[0..plaintext.len],
        tag,
        plaintext,
        associated_data,
        nonce.*,
        key.*,
    );
}

/// Decrypt data using AES-256-GCM
///
/// Parameters:
/// - key: 32-byte encryption key
/// - nonce: 12-byte nonce (same as used for encryption)
/// - ciphertext: Encrypted data
/// - plaintext: Output buffer (must be same length as ciphertext)
/// - tag: Authentication tag from encryption (16 bytes)
/// - associated_data: Additional authenticated data (must match encryption)
///
/// Returns error.AuthenticationFailed if tag verification fails
pub fn decrypt(
    key: *const [key_size]u8,
    nonce: *const [nonce_size]u8,
    ciphertext: []const u8,
    plaintext: []u8,
    tag: *const [tag_size]u8,
    associated_data: []const u8,
) AeadError!void {
    if (plaintext.len < ciphertext.len) {
        return error.InvalidKeySize; // Reusing error for buffer size
    }

    crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        plaintext[0..ciphertext.len],
        ciphertext,
        tag.*,
        associated_data,
        nonce.*,
        key.*,
    ) catch {
        return error.AuthenticationFailed;
    };
}

// ============================================================================
// Tests
// ============================================================================

test "AES-256-GCM encrypt/decrypt round-trip" {
    const testing = std.testing;

    const key = [_]u8{0x01} ** key_size;
    const nonce = [_]u8{0x02} ** nonce_size;
    const plaintext = "Hello, World!";
    const associated_data = "metadata";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_size]u8 = undefined;

    // Encrypt
    try encrypt(&key, &nonce, plaintext, &ciphertext, &tag, associated_data);

    // Verify ciphertext is different from plaintext
    try testing.expect(!std.mem.eql(u8, plaintext, &ciphertext));

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try decrypt(&key, &nonce, &ciphertext, &decrypted, &tag, associated_data);

    // Verify round-trip
    try testing.expectEqualStrings(plaintext, &decrypted);
}

test "AES-256-GCM authentication failure with wrong tag" {
    const testing = std.testing;

    const key = [_]u8{0x01} ** key_size;
    const nonce = [_]u8{0x02} ** nonce_size;
    const plaintext = "Secret message";
    const associated_data = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_size]u8 = undefined;

    try encrypt(&key, &nonce, plaintext, &ciphertext, &tag, associated_data);

    // Corrupt the tag
    tag[0] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        decrypt(&key, &nonce, &ciphertext, &decrypted, &tag, associated_data)
    );
}

test "AES-256-GCM authentication failure with wrong key" {
    const testing = std.testing;

    const key = [_]u8{0x01} ** key_size;
    const wrong_key = [_]u8{0xFF} ** key_size;
    const nonce = [_]u8{0x02} ** nonce_size;
    const plaintext = "Secret message";
    const associated_data = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_size]u8 = undefined;

    try encrypt(&key, &nonce, plaintext, &ciphertext, &tag, associated_data);

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        decrypt(&wrong_key, &nonce, &ciphertext, &decrypted, &tag, associated_data)
    );
}

test "AES-256-GCM with empty plaintext" {
    const testing = std.testing;

    const key = [_]u8{0x01} ** key_size;
    const nonce = [_]u8{0x02} ** nonce_size;
    const plaintext = "";
    const associated_data = "just metadata";

    var tag: [tag_size]u8 = undefined;

    // Encrypt empty data
    var ciphertext: [0]u8 = undefined;
    try encrypt(&key, &nonce, plaintext, &ciphertext, &tag, associated_data);

    // Decrypt
    var decrypted: [0]u8 = undefined;
    try decrypt(&key, &nonce, &ciphertext, &decrypted, &tag, associated_data);

    try testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "AES-256-GCM with different associated data fails" {
    const testing = std.testing;

    const key = [_]u8{0x01} ** key_size;
    const nonce = [_]u8{0x02} ** nonce_size;
    const plaintext = "Message";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_size]u8 = undefined;

    try encrypt(&key, &nonce, plaintext, &ciphertext, &tag, "metadata1");

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        decrypt(&key, &nonce, &ciphertext, &decrypted, &tag, "metadata2")
    );
}
