const std = @import("std");
const crypto = std.crypto;

/// SHA-256 hash output size
pub const sha256_size = 32;

/// Compute SHA-256 hash of data
pub fn sha256(data: []const u8) [sha256_size]u8 {
    var hash: [sha256_size]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return hash;
}

/// Incremental SHA-256 hasher
pub const Sha256 = struct {
    hasher: crypto.hash.sha2.Sha256,

    pub fn init() Sha256 {
        return .{ .hasher = crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *Sha256, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn final(self: *Sha256) [sha256_size]u8 {
        var hash: [sha256_size]u8 = undefined;
        self.hasher.final(&hash);
        return hash;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SHA-256 empty string" {
    const testing = std.testing;
    
    const hash = sha256("");
    
    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    
    try testing.expectEqualSlices(u8, &expected, &hash);
}

test "SHA-256 hello world" {
    const testing = std.testing;
    
    const hash = sha256("hello world");
    
    // SHA-256 of "hello world"
    const expected = [_]u8{
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
        0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
        0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
        0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
    };
    
    try testing.expectEqualSlices(u8, &expected, &hash);
}

test "SHA-256 incremental" {
    const testing = std.testing;
    
    var hasher = Sha256.init();
    hasher.update("hello");
    hasher.update(" ");
    hasher.update("world");
    const hash = hasher.final();
    
    // Should match single-call hash
    const expected = sha256("hello world");
    try testing.expectEqualSlices(u8, &expected, &hash);
}

test "SHA-256 binary data" {
    const testing = std.testing;
    
    const data = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD };
    const hash = sha256(&data);
    
    // Verify hash is not all zeros
    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}
