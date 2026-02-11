const std = @import("std");
const Allocator = std.mem.Allocator;

/// Wire encoding errors
pub const WireError = error{
    BufferTooSmall,
    EndOfBuffer,
    InvalidEncoding,
    InvalidString,
    InvalidMpint,
    OutOfRange,
};

/// Reader for decoding SSH wire format from a buffer
pub const Reader = struct {
    buffer: []const u8,
    offset: usize = 0,

    pub fn init(buffer: []const u8) Reader {
        return .{ .buffer = buffer };
    }

    /// Get remaining bytes in buffer
    pub fn remaining(self: Reader) usize {
        return self.buffer.len - self.offset;
    }

    /// Check if at end of buffer
    pub fn isAtEnd(self: Reader) bool {
        return self.offset >= self.buffer.len;
    }

    /// Peek at next byte without consuming
    pub fn peek(self: Reader) ?u8 {
        if (self.offset >= self.buffer.len) return null;
        return self.buffer[self.offset];
    }

    /// Read raw bytes into destination
    pub fn readBytes(self: *Reader, dest: []u8) WireError!void {
        if (self.remaining() < dest.len) return error.EndOfBuffer;
        @memcpy(dest, self.buffer[self.offset..][0..dest.len]);
        self.offset += dest.len;
    }

    /// Read a single byte
    pub fn readByte(self: *Reader) WireError!u8 {
        if (self.offset >= self.buffer.len) return error.EndOfBuffer;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    /// Read a boolean (encoded as byte: 0 = false, 1 = true)
    pub fn readBoolean(self: *Reader) WireError!bool {
        const value = try self.readByte();
        return value != 0;
    }

    /// Read uint32 in big-endian format
    pub fn readUint32(self: *Reader) WireError!u32 {
        if (self.remaining() < 4) return error.EndOfBuffer;
        const value = std.mem.readInt(u32, self.buffer[self.offset..][0..4], .big);
        self.offset += 4;
        return value;
    }

    /// Read uint64 in big-endian format
    pub fn readUint64(self: *Reader) WireError!u64 {
        if (self.remaining() < 8) return error.EndOfBuffer;
        const value = std.mem.readInt(u64, self.buffer[self.offset..][0..8], .big);
        self.offset += 8;
        return value;
    }
};

/// Writer for encoding SSH wire format to a buffer
pub const Writer = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    /// Get remaining space in buffer
    pub fn remaining(self: Writer) usize {
        return self.buffer.len - self.offset;
    }

    /// Get bytes written so far
    pub fn written(self: Writer) []const u8 {
        return self.buffer[0..self.offset];
    }

    /// Write raw bytes from source
    pub fn writeBytes(self: *Writer, src: []const u8) WireError!void {
        if (self.remaining() < src.len) return error.BufferTooSmall;
        @memcpy(self.buffer[self.offset..][0..src.len], src);
        self.offset += src.len;
    }

    /// Write a single byte
    pub fn writeByte(self: *Writer, value: u8) WireError!void {
        if (self.offset >= self.buffer.len) return error.BufferTooSmall;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    /// Write a boolean (encoded as byte: 0 = false, 1 = true)
    pub fn writeBoolean(self: *Writer, value: bool) WireError!void {
        try self.writeByte(if (value) 1 else 0);
    }

    /// Write uint32 in big-endian format
    pub fn writeUint32(self: *Writer, value: u32) WireError!void {
        if (self.remaining() < 4) return error.BufferTooSmall;
        std.mem.writeInt(u32, self.buffer[self.offset..][0..4], value, .big);
        self.offset += 4;
    }

    /// Write uint64 in big-endian format
    pub fn writeUint64(self: *Writer, value: u64) WireError!void {
        if (self.remaining() < 8) return error.BufferTooSmall;
        std.mem.writeInt(u64, self.buffer[self.offset..][0..8], value, .big);
        self.offset += 8;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Reader and Writer - byte" {
    const testing = std.testing;

    var buf: [16]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write bytes
    try writer.writeByte(42);
    try writer.writeByte(0);
    try writer.writeByte(255);

    // Read them back
    var reader = Reader.init(writer.written());
    try testing.expectEqual(@as(u8, 42), try reader.readByte());
    try testing.expectEqual(@as(u8, 0), try reader.readByte());
    try testing.expectEqual(@as(u8, 255), try reader.readByte());
    try testing.expect(reader.isAtEnd());
}

test "Reader and Writer - boolean" {
    const testing = std.testing;

    var buf: [16]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write booleans
    try writer.writeBoolean(true);
    try writer.writeBoolean(false);
    try writer.writeBoolean(true);

    // Read them back
    var reader = Reader.init(writer.written());
    try testing.expectEqual(true, try reader.readBoolean());
    try testing.expectEqual(false, try reader.readBoolean());
    try testing.expectEqual(true, try reader.readBoolean());
}

test "Reader and Writer - uint32" {
    const testing = std.testing;

    var buf: [32]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write uint32 values
    try writer.writeUint32(0);
    try writer.writeUint32(1);
    try writer.writeUint32(0x12345678);
    try writer.writeUint32(0xFFFFFFFF);

    // Read them back
    var reader = Reader.init(writer.written());
    try testing.expectEqual(@as(u32, 0), try reader.readUint32());
    try testing.expectEqual(@as(u32, 1), try reader.readUint32());
    try testing.expectEqual(@as(u32, 0x12345678), try reader.readUint32());
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), try reader.readUint32());
}

test "Reader and Writer - uint64" {
    const testing = std.testing;

    var buf: [64]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write uint64 values
    try writer.writeUint64(0);
    try writer.writeUint64(1);
    try writer.writeUint64(0x123456789ABCDEF0);
    try writer.writeUint64(0xFFFFFFFFFFFFFFFF);

    // Read them back
    var reader = Reader.init(writer.written());
    try testing.expectEqual(@as(u64, 0), try reader.readUint64());
    try testing.expectEqual(@as(u64, 1), try reader.readUint64());
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), try reader.readUint64());
    try testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), try reader.readUint64());
}

test "Reader - EndOfBuffer error" {
    const testing = std.testing;

    const buf = [_]u8{ 1, 2, 3 };
    var reader = Reader.init(&buf);

    // Read all bytes
    _ = try reader.readByte();
    _ = try reader.readByte();
    _ = try reader.readByte();

    // Should fail on next read
    try testing.expectError(error.EndOfBuffer, reader.readByte());
    try testing.expectError(error.EndOfBuffer, reader.readUint32());
    try testing.expectError(error.EndOfBuffer, reader.readUint64());
}

test "Writer - BufferTooSmall error" {
    const testing = std.testing;

    var buf: [2]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write 2 bytes (should succeed)
    try writer.writeByte(1);
    try writer.writeByte(2);

    // Next write should fail
    try testing.expectError(error.BufferTooSmall, writer.writeByte(3));
}

test "Reader - peek and remaining" {
    const testing = std.testing;

    const buf = [_]u8{ 1, 2, 3, 4 };
    var reader = Reader.init(&buf);

    try testing.expectEqual(@as(usize, 4), reader.remaining());
    try testing.expectEqual(@as(?u8, 1), reader.peek());
    try testing.expectEqual(@as(?u8, 1), reader.peek()); // Peek doesn't advance

    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 3), reader.remaining());
    try testing.expectEqual(@as(?u8, 2), reader.peek());

    _ = try reader.readByte();
    _ = try reader.readByte();
    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 0), reader.remaining());
    try testing.expectEqual(@as(?u8, null), reader.peek());
    try testing.expect(reader.isAtEnd());
}

test "Writer - written and remaining" {
    const testing = std.testing;

    var buf: [10]u8 = undefined;
    var writer = Writer.init(&buf);

    try testing.expectEqual(@as(usize, 10), writer.remaining());
    try testing.expectEqual(@as(usize, 0), writer.written().len);

    try writer.writeByte(42);
    try testing.expectEqual(@as(usize, 9), writer.remaining());
    try testing.expectEqual(@as(usize, 1), writer.written().len);
    try testing.expectEqual(@as(u8, 42), writer.written()[0]);

    try writer.writeUint32(0x12345678);
    try testing.expectEqual(@as(usize, 5), writer.remaining());
    try testing.expectEqual(@as(usize, 5), writer.written().len);
}

test "Round-trip encoding - mixed types" {
    const testing = std.testing;

    var buf: [100]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write mixed data
    try writer.writeByte(123);
    try writer.writeBoolean(true);
    try writer.writeUint32(0xDEADBEEF);
    try writer.writeBoolean(false);
    try writer.writeUint64(0x0123456789ABCDEF);
    try writer.writeByte(255);

    // Read it all back
    var reader = Reader.init(writer.written());
    try testing.expectEqual(@as(u8, 123), try reader.readByte());
    try testing.expectEqual(true, try reader.readBoolean());
    try testing.expectEqual(@as(u32, 0xDEADBEEF), try reader.readUint32());
    try testing.expectEqual(false, try reader.readBoolean());
    try testing.expectEqual(@as(u64, 0x0123456789ABCDEF), try reader.readUint64());
    try testing.expectEqual(@as(u8, 255), try reader.readByte());
    try testing.expect(reader.isAtEnd());
}

test "Big-endian encoding verification" {
    const testing = std.testing;

    var buf: [8]u8 = undefined;
    var writer = Writer.init(&buf);

    // Write uint32 in big-endian
    try writer.writeUint32(0x12345678);

    // Verify byte order (big-endian = most significant byte first)
    try testing.expectEqual(@as(u8, 0x12), buf[0]);
    try testing.expectEqual(@as(u8, 0x34), buf[1]);
    try testing.expectEqual(@as(u8, 0x56), buf[2]);
    try testing.expectEqual(@as(u8, 0x78), buf[3]);

    // Write uint64 in big-endian
    writer.offset = 0; // Reset
    try writer.writeUint64(0x123456789ABCDEF0);

    try testing.expectEqual(@as(u8, 0x12), buf[0]);
    try testing.expectEqual(@as(u8, 0x34), buf[1]);
    try testing.expectEqual(@as(u8, 0x56), buf[2]);
    try testing.expectEqual(@as(u8, 0x78), buf[3]);
    try testing.expectEqual(@as(u8, 0x9A), buf[4]);
    try testing.expectEqual(@as(u8, 0xBC), buf[5]);
    try testing.expectEqual(@as(u8, 0xDE), buf[6]);
    try testing.expectEqual(@as(u8, 0xF0), buf[7]);
}
