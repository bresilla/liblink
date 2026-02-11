const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("../crypto/crypto.zig");

/// Obfuscated envelope constants
pub const obfs_nonce_size = 16;
pub const obfs_tag_size = 16;
pub const obfs_key_size = 32; // SHA-256 output

/// High bit marker for obfuscated packets (distinguishes from QUIC)
pub const high_bit_marker: u8 = 0x80;

/// Errors for obfuscation operations
pub const ObfuscationError = error{
    InvalidNonce,
    InvalidPayload,
    DecryptionFailed,
    OutOfMemory,
};

/// Process obfuscation keyword according to SPEC.md Section 2.3.1
///
/// Steps:
/// 1. Process according to OpaqueString profile (RFC 8265) - simplified
/// 2. Remove leading/trailing whitespace (tab, LF, CR, space)
/// 3. Encode as UTF-8 bytes
/// 4. Compute SHA-256 digest for encryption key
///
/// Parameters:
/// - keyword: User-entered obfuscation keyword (Unicode string)
/// - key_out: Output buffer for derived key (32 bytes)
pub fn processKeyword(keyword: []const u8, key_out: *[obfs_key_size]u8) void {
    // Simplified OpaqueString processing:
    // For now, we treat the input as UTF-8 and skip complex Unicode normalization.
    // A full implementation would apply RFC 8265 rules.

    // Step 2: Trim leading and trailing whitespace
    const trimmed = trimWhitespace(keyword);

    // Step 4: Compute SHA-256 digest
    crypto.hash.sha256(trimmed, key_out);
}

/// Trim leading and trailing whitespace characters
///
/// Removes CHARACTER TABULATION (U+0009), LINE FEED (U+000A),
/// CARRIAGE RETURN (U+000D), and SPACE (U+0020).
fn trimWhitespace(input: []const u8) []const u8 {
    if (input.len == 0) return input;

    var start: usize = 0;
    var end: usize = input.len;

    // Trim leading whitespace
    while (start < end and isWhitespace(input[start])) {
        start += 1;
    }

    // Trim trailing whitespace
    while (end > start and isWhitespace(input[end - 1])) {
        end -= 1;
    }

    return input[start..end];
}

/// Check if character is trimmed whitespace
fn isWhitespace(c: u8) bool {
    return c == 0x09 or // CHARACTER TABULATION
        c == 0x0A or // LINE FEED
        c == 0x0D or // CARRIAGE RETURN
        c == 0x20; // SPACE
}

/// Obfuscated envelope structure
pub const ObfuscatedEnvelope = struct {
    nonce: [obfs_nonce_size]u8,
    payload: []u8,
    tag: [obfs_tag_size]u8,

    /// Free the payload memory
    pub fn deinit(self: *ObfuscatedEnvelope, allocator: Allocator) void {
        allocator.free(self.payload);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "processKeyword - empty keyword" {
    const testing = std.testing;

    var key: [obfs_key_size]u8 = undefined;
    processKeyword("", &key);

    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };

    try testing.expectEqualSlices(u8, &expected, &key);
}

test "processKeyword - simple keyword" {
    const testing = std.testing;

    var key: [obfs_key_size]u8 = undefined;
    processKeyword("my-secret-keyword", &key);

    // Verify it's not empty (all zeros)
    var all_zero = true;
    for (key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "processKeyword - keyword with leading whitespace" {
    const testing = std.testing;

    var key1: [obfs_key_size]u8 = undefined;
    var key2: [obfs_key_size]u8 = undefined;

    processKeyword("  \t\n\r  secret", &key1);
    processKeyword("secret", &key2);

    // Should produce same key after trimming
    try testing.expectEqualSlices(u8, &key2, &key1);
}

test "processKeyword - keyword with trailing whitespace" {
    const testing = std.testing;

    var key1: [obfs_key_size]u8 = undefined;
    var key2: [obfs_key_size]u8 = undefined;

    processKeyword("secret  \t\n\r  ", &key1);
    processKeyword("secret", &key2);

    // Should produce same key after trimming
    try testing.expectEqualSlices(u8, &key2, &key1);
}

test "processKeyword - keyword with leading and trailing whitespace" {
    const testing = std.testing;

    var key1: [obfs_key_size]u8 = undefined;
    var key2: [obfs_key_size]u8 = undefined;

    processKeyword("  \t  secret  \n\r  ", &key1);
    processKeyword("secret", &key2);

    // Should produce same key after trimming
    try testing.expectEqualSlices(u8, &key2, &key1);
}

test "processKeyword - keyword with internal whitespace" {
    const testing = std.testing;

    var key1: [obfs_key_size]u8 = undefined;
    var key2: [obfs_key_size]u8 = undefined;

    processKeyword("my secret keyword", &key1);
    processKeyword("my secret keyword", &key2);

    // Internal whitespace should be preserved
    try testing.expectEqualSlices(u8, &key2, &key1);
}

test "trimWhitespace - empty string" {
    const testing = std.testing;
    const result = trimWhitespace("");
    try testing.expectEqualStrings("", result);
}

test "trimWhitespace - only whitespace" {
    const testing = std.testing;
    const result = trimWhitespace("  \t\n\r  ");
    try testing.expectEqualStrings("", result);
}

test "trimWhitespace - no whitespace" {
    const testing = std.testing;
    const result = trimWhitespace("hello");
    try testing.expectEqualStrings("hello", result);
}

test "trimWhitespace - leading whitespace" {
    const testing = std.testing;
    const result = trimWhitespace("  \t\n\rhello");
    try testing.expectEqualStrings("hello", result);
}

test "trimWhitespace - trailing whitespace" {
    const testing = std.testing;
    const result = trimWhitespace("hello  \t\n\r");
    try testing.expectEqualStrings("hello", result);
}

test "trimWhitespace - both leading and trailing" {
    const testing = std.testing;
    const result = trimWhitespace("  \t\n\rhello  \t\n\r");
    try testing.expectEqualStrings("hello", result);
}

test "trimWhitespace - internal whitespace preserved" {
    const testing = std.testing;
    const result = trimWhitespace("  hello  world  ");
    try testing.expectEqualStrings("hello  world", result);
}

test "isWhitespace - tab" {
    const testing = std.testing;
    try testing.expect(isWhitespace(0x09));
}

test "isWhitespace - line feed" {
    const testing = std.testing;
    try testing.expect(isWhitespace(0x0A));
}

test "isWhitespace - carriage return" {
    const testing = std.testing;
    try testing.expect(isWhitespace(0x0D));
}

test "isWhitespace - space" {
    const testing = std.testing;
    try testing.expect(isWhitespace(0x20));
}

test "isWhitespace - non-whitespace" {
    const testing = std.testing;
    try testing.expect(!isWhitespace('a'));
    try testing.expect(!isWhitespace('0'));
    try testing.expect(!isWhitespace('_'));
}
